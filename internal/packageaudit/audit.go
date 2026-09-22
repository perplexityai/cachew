// Package packageaudit writes bounded, best-effort package audit records for a separate log collector.
package packageaudit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/errors"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/block/cachew/internal/metrics"
)

const (
	queueCapacity = 4096
	maxRecordSize = 8 * 1024
	maxFileSize   = 16 * 1024 * 1024
	maxFiles      = 16
	filePrefix    = "package-audit-"
	warnInterval  = time.Minute
)

// Config enables local audit delivery; the directory must be dedicated to one Cachew process and its collector.
type Config struct {
	Directory string `hcl:"directory,optional" help:"Required when enabled: private directory for bounded package audit NDJSON files."`
}

// Event deliberately excludes unverified identity, request headers, URLs, and provider response bodies.
type Event struct {
	SchemaVersion     int       `json:"schema_version"`
	EventID           string    `json:"event_id"`
	Timestamp         time.Time `json:"timestamp"`
	PURL              string    `json:"purl,omitempty"`
	PackageRedacted   bool      `json:"package_redacted"`
	ActorType         string    `json:"actor_type"`
	PolicyMode        string    `json:"policy_mode"`
	PolicyVerdict     string    `json:"policy_verdict"`
	PolicyError       string    `json:"policy_error,omitempty"`
	PolicyAction      string    `json:"policy_action"`
	VerdictCacheHit   bool      `json:"verdict_cache_hit"`
	ResponseSource    string    `json:"response_source"`
	HTTPStatus        int       `json:"http_status"`
	PolicyDurationMS  float64   `json:"policy_duration_ms"`
	RequestDurationMS float64   `json:"request_duration_ms"`
}

// Sink keeps disk and collector latency off request handlers. Close it after HTTP handlers have drained.
type Sink struct {
	mu         sync.RWMutex
	closed     bool
	queue      chan []byte
	done       chan struct{}
	closeErr   error
	logger     *slog.Logger
	root       *os.Root
	lock       *os.File
	file       *os.File
	size       int64
	files      []string
	fileSize   int64
	fileLimit  int
	events     metric.Int64Counter
	evictions  metric.Int64Counter
	syncErrors metric.Int64Counter
	dropped    atomic.Int64
	evicted    atomic.Int64
	unsynced   atomic.Int64
	lastWarn   time.Time
}

type contextKey struct{}

// ContextWithSink makes the optional audit sink available to configured strategies and HTTP handlers.
func ContextWithSink(ctx context.Context, sink *Sink) context.Context {
	return context.WithValue(ctx, contextKey{}, sink)
}

// FromContext returns nil when package audit collection is disabled.
func FromContext(ctx context.Context) *Sink {
	sink, _ := ctx.Value(contextKey{}).(*Sink)
	return sink
}

// New opens a private, bounded spool without making any network requests.
func New(config Config, logger *slog.Logger) (*Sink, error) {
	if config.Directory == "" || !filepath.IsAbs(config.Directory) {
		return nil, errors.Errorf("package audit directory must be a nonempty absolute path")
	}
	if err := os.MkdirAll(config.Directory, 0700); err != nil {
		return nil, errors.Errorf("create package audit directory: %w", err)
	}
	info, err := os.Lstat(config.Directory)
	if err != nil {
		return nil, errors.Errorf("inspect package audit directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.Errorf("package audit directory must be a private directory (0700)")
	}
	root, err := os.OpenRoot(config.Directory)
	if err != nil {
		return nil, errors.Errorf("open package audit directory: %w", err)
	}
	lock, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		_ = root.Close()
		return nil, errors.Errorf("open package audit lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // OS file descriptors fit in int.
		_ = lock.Close()
		_ = root.Close()
		return nil, errors.Errorf("lock package audit directory: %w", err)
	}
	meter := otel.Meter("cachew.package_audit")
	sink := &Sink{
		queue: make(chan []byte, queueCapacity), done: make(chan struct{}), logger: logger,
		root: root, lock: lock, fileSize: maxFileSize, fileLimit: maxFiles,
		events: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.events_total", "{events}",
			"Audit events written locally or dropped; local writes do not confirm collector delivery"),
		evictions: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.retention_evictions_total", "{files}",
			"Audit files removed at the spool limit, with collector delivery unknown"),
		syncErrors: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.sync_errors_total", "{errors}",
			"Audit file sync failures; previously written records may not be durable"),
	}
	if err := sink.loadFiles(); err != nil {
		_ = lock.Close()
		_ = root.Close()
		return nil, err
	}
	if err := sink.rotate(); err != nil {
		_ = lock.Close()
		_ = root.Close()
		return nil, err
	}
	go sink.run()
	return sink, nil
}

// Record never waits for queue capacity, disk I/O, or a collector. Oversized and overflowing events are counted as dropped.
func (s *Sink) Record(event Event) {
	if s == nil {
		return
	}
	if event.PackageRedacted {
		event.PURL = ""
	}
	if len(event.PURL)+len(event.PolicyMode)+len(event.PolicyVerdict)+len(event.PolicyError)+
		len(event.PolicyAction)+len(event.ResponseSource) > maxRecordSize/2 {
		s.drop("invalid")
		return
	}
	event.SchemaVersion, event.EventID, event.ActorType = 1, uuid.NewString(), "unknown"
	event.Timestamp = time.Now().UTC()
	data, err := json.Marshal(event)
	if err != nil || len(data)+1 > maxRecordSize {
		s.drop("invalid")
		return
	}
	data = append(data, '\n')
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.drop("closed")
		return
	}
	select {
	case s.queue <- data:
	default:
		s.drop("queue_full")
	}
}

// Close drains accepted records, syncs the last file, and releases the directory lock. It is safe to call more than once.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	<-s.done
	return s.closeErr
}

func (s *Sink) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer close(s.done)
	for {
		select {
		case data, ok := <-s.queue:
			if !ok {
				s.closeErr = s.closeFile()
				if err := s.lock.Close(); s.closeErr == nil {
					s.closeErr = err
				}
				if err := s.root.Close(); s.closeErr == nil {
					s.closeErr = err
				}
				s.report(true)
				return
			}
			if err := s.write(data); err != nil {
				s.drop("write_error")
			} else {
				s.events.Add(context.Background(), 1, metric.WithAttributes(attribute.String("result", "written")))
			}
		case <-ticker.C:
			if s.file != nil {
				if err := s.syncFile(); err != nil {
					s.report(false)
				}
			}
		}
		s.report(false)
	}
}

func (s *Sink) write(data []byte) error {
	if s.file == nil || s.size+int64(len(data)) > s.fileSize {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	if _, err := s.file.Write(data); err != nil {
		rollbackErr := s.file.Truncate(s.size)
		closeErr := s.closeFile()
		return errors.Errorf("write package audit record: %w", errors.Join(err, rollbackErr, closeErr))
	}
	s.size += int64(len(data))
	return nil
}

func (s *Sink) closeFile() error {
	if s.file == nil {
		return nil
	}
	err := s.syncFile()
	closeErr := s.file.Close()
	s.file = nil
	if err != nil {
		return err
	}
	if closeErr != nil {
		return errors.Errorf("close package audit file: %w", closeErr)
	}
	return nil
}

func (s *Sink) syncFile() error {
	if err := s.file.Sync(); err != nil {
		s.syncErrors.Add(context.Background(), 1)
		s.unsynced.Add(1)
		return errors.Errorf("sync package audit file: %w", err)
	}
	return nil
}

func (s *Sink) rotate() error {
	if err := s.closeFile(); err != nil {
		return err
	}
	name := filePrefix + time.Now().UTC().Format("20060102T150405.000000000") + "-" + uuid.NewString() + ".ndjson"
	file, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Errorf("create package audit file: %w", err)
	}
	// ponytail: a bounded local spool cannot know whether the collector delivered an old file. Evictions are visible;
	// use an acknowledged durable transport if retaining every record through an unbounded collector outage is required.
	for len(s.files) >= s.fileLimit {
		if err := s.root.Remove(s.files[0]); err != nil && !os.IsNotExist(err) {
			closeErr := file.Close()
			removeErr := s.root.Remove(name)
			return errors.Errorf("remove expired package audit file: %w", errors.Join(err, closeErr, removeErr))
		}
		s.files = s.files[1:]
		s.evictions.Add(context.Background(), 1)
		s.evicted.Add(1)
	}
	s.file, s.size = file, 0
	s.files = append(s.files, name)
	return nil
}

func (s *Sink) loadFiles() error {
	dir, err := s.root.Open(".")
	if err != nil {
		return errors.Errorf("open package audit file listing: %w", err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return errors.Errorf("list package audit files: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filePrefix) && strings.HasSuffix(entry.Name(), ".ndjson") {
			if !entry.Type().IsRegular() {
				return errors.Errorf("package audit spool contains a non-regular audit file")
			}
			s.files = append(s.files, entry.Name())
		}
	}
	slices.Sort(s.files)
	return nil
}

func (s *Sink) drop(reason string) {
	s.events.Add(context.Background(), 1, metric.WithAttributes(attribute.String("result", "dropped_"+reason)))
	s.dropped.Add(1)
}

func (s *Sink) report(force bool) {
	if !force && time.Since(s.lastWarn) < warnInterval {
		return
	}
	s.lastWarn = time.Now()
	dropped, evicted, unsynced := s.dropped.Swap(0), s.evicted.Swap(0), s.unsynced.Swap(0)
	if dropped != 0 || evicted != 0 || unsynced != 0 {
		s.logger.Warn("Package audit delivery incomplete or uncertain", "dropped_events", dropped,
			"retention_evictions_delivery_unknown", evicted, "sync_errors", unsynced)
	}
}
