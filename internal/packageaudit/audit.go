// Package packageaudit writes bounded, best-effort package audit records for a separate log collector.
package packageaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
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
	mu               sync.RWMutex
	closed           bool
	queue            chan []byte
	done             chan struct{}
	stop             chan struct{}
	stopOnce         sync.Once
	closeErr         error
	logger           *slog.Logger
	root             *os.Root
	lock             *os.File
	file             *os.File
	name             string
	sequence         uint64
	rollback         bool
	size             int64
	files            []string
	fileSize         int64
	fileLimit        int
	events           metric.Int64Counter
	evictions        metric.Int64Counter
	syncErrors       metric.Int64Counter
	retentionErrors  metric.Int64Counter
	shutdownTimeouts metric.Int64Counter
	dropped          atomic.Int64
	evicted          atomic.Int64
	unsynced         atomic.Int64
	unpruned         atomic.Int64
	lastWarn         time.Time
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
	root, err := openAuditRoot(config.Directory)
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
		queue: make(chan []byte, queueCapacity), done: make(chan struct{}), stop: make(chan struct{}), logger: logger,
		root: root, lock: lock, fileSize: maxFileSize, fileLimit: maxFiles,
		events: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.events_total", "{events}",
			"Audit events written locally or dropped; local writes do not confirm collector delivery"),
		evictions: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.retention_evictions_total", "{files}",
			"Audit files removed at the spool limit, with collector delivery unknown"),
		syncErrors: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.sync_errors_total", "{errors}",
			"Audit file sync failures; previously written records may not be durable"),
		retentionErrors: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.retention_errors_total", "{errors}",
			"Audit retention failures; further writes pause until pruning succeeds"),
		shutdownTimeouts: metrics.NewMetric[metric.Int64Counter](meter, "cachew.package_audit.shutdown_timeouts_total", "{timeouts}",
			"Audit drains abandoned at the caller deadline; delivery is uncertain"),
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

// Close drains and syncs until ctx expires. A deadline abandons queued records; an in-progress disk syscall can outlive
// Close, retaining the directory lock until it returns or the process exits. It is safe to call more than once.
func (s *Sink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return s.closeErr
	default:
	}
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		s.stopOnce.Do(func() {
			close(s.stop)
			s.shutdownTimeouts.Add(context.Background(), 1)
		})
		return errors.Wrap(ctx.Err(), "package audit shutdown incomplete")
	}
}

func (s *Sink) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer close(s.done)
	defer func() {
		s.closeErr = errors.Join(s.closeErr, s.closeFile(), s.lock.Close(), s.root.Close())
		s.report(true)
	}()
	for {
		select {
		case <-s.stop:
			for range s.queue {
				s.drop("shutdown_timeout")
			}
			s.closeErr = context.Canceled
			return
		default:
		}
		select {
		case <-s.stop:
			continue
		case data, ok := <-s.queue:
			if !ok {
				return
			}
			if err := s.write(data); err != nil {
				s.drop("write_error")
				// Disk faults must not consume the entire queue in a tight loop. Request admission stays nonblocking.
				select {
				case <-time.After(time.Second):
				case <-s.stop:
				}
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
	if len(s.files) > s.fileLimit {
		if err := s.prune(); err != nil {
			return err
		}
	}
	if s.rollback {
		if err := s.file.Truncate(s.size); err != nil {
			return errors.Errorf("repair partial package audit record: %w", err)
		}
		s.rollback = false
	}
	if s.file == nil || s.size+int64(len(data)) > s.fileSize {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.file.WriteAt(data, s.size)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.rollback = true
		rollbackErr := s.file.Truncate(s.size)
		s.rollback = rollbackErr != nil
		return errors.Errorf("write package audit record: %w", errors.Join(err, rollbackErr))
	}
	first := s.size == 0
	s.size += int64(len(data))
	if first {
		s.files = append(s.files, s.name)
		// A failed first write must never evict retained history. A failed eviction leaves at most one extra segment;
		// the next write cannot proceed until pruning succeeds. The successful record is still counted as written.
		if err := s.prune(); err != nil {
			s.report(false)
		}
	}
	return nil
}

func (s *Sink) closeFile() error {
	if s.file == nil {
		return nil
	}
	err := s.syncFile()
	closeErr := s.file.Close()
	s.file = nil
	if s.size == 0 {
		closeErr = errors.Join(closeErr, s.root.Remove(s.name))
	}
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
	if s.sequence == ^uint64(0) {
		return errors.New("package audit segment sequence exhausted")
	}
	s.sequence++
	name := fmt.Sprintf("%s%020d-%s.ndjson", filePrefix, s.sequence, uuid.NewString())
	file, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Errorf("create package audit file: %w", err)
	}
	s.file, s.name, s.size, s.rollback = file, name, 0, false
	return nil
}

func (s *Sink) prune() (err error) {
	defer func() {
		if err != nil {
			s.retentionErrors.Add(context.Background(), 1)
			s.unpruned.Add(1)
		}
	}()
	// Refresh all missing entries first: a collector removing a newer file must not cause an unnecessary old eviction.
	for i := 0; i < len(s.files); {
		if _, err := s.root.Stat(s.files[i]); os.IsNotExist(err) {
			s.files = slices.Delete(s.files, i, i+1)
		} else if err != nil {
			return errors.Errorf("inspect retained package audit file: %w", err)
		} else {
			i++
		}
	}
	// A bounded local spool cannot confirm collector delivery, so only files this process actually removes count as
	// evictions. Surviving an unbounded collector outage would need an acknowledged durable transport instead.
	for len(s.files) > s.fileLimit {
		err := s.root.Remove(s.files[0])
		if err != nil && !os.IsNotExist(err) {
			return errors.Errorf("remove expired package audit file: %w", err)
		}
		s.files = s.files[1:]
		if err == nil {
			s.evictions.Add(context.Background(), 1)
			s.evicted.Add(1)
		}
	}
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
	var legacy []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filePrefix) && strings.HasSuffix(entry.Name(), ".ndjson") {
			if !entry.Type().IsRegular() {
				return errors.Errorf("package audit spool contains a non-regular audit file")
			}
			info, err := entry.Info()
			if err != nil {
				return errors.Errorf("inspect retained package audit file: %w", err)
			}
			prefix, _, _ := strings.Cut(strings.TrimPrefix(entry.Name(), filePrefix), "-")
			sequence, err := strconv.ParseUint(prefix, 10, 64)
			if err == nil && len(prefix) == 20 {
				s.sequence = max(s.sequence, sequence)
				if info.Size() != 0 {
					s.files = append(s.files, entry.Name())
				}
			} else if info.Size() != 0 {
				// Preserve pre-sequence spool files, ordering them before all new writes. Their historical wall-clock
				// order cannot be reconstructed, but clock changes can no longer reorder new segments after restart.
				legacy = append(legacy, entry.Name())
			}
			if info.Size() == 0 {
				// A crash before the first write must not accumulate untracked empty segments on each restart.
				if err := s.root.Remove(entry.Name()); err != nil && !os.IsNotExist(err) {
					return errors.Errorf("remove empty package audit segment: %w", err)
				}
			}
		}
	}
	slices.Sort(s.files)
	slices.Sort(legacy)
	s.files = append(legacy, s.files...)
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
	dropped, evicted, unsynced, unpruned := s.dropped.Swap(0), s.evicted.Swap(0), s.unsynced.Swap(0), s.unpruned.Swap(0)
	if dropped != 0 || evicted != 0 || unsynced != 0 || unpruned != 0 {
		s.logger.Warn("Package audit delivery incomplete or uncertain", "dropped_events", dropped,
			"retention_evictions_delivery_unknown", evicted, "sync_errors", unsynced, "retention_errors", unpruned)
	}
}
