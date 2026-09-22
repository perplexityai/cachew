package packageaudit //nolint:testpackage // Exercises queue overflow and disk failures without an external collector.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/google/uuid"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const testPURL = "pkg:npm/example@1.2.3"

func TestWriterDrainsRedactsAndLocks(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "audit")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sink, err := New(Config{Directory: directory}, logger.Warn)
	assert.NoError(t, err)
	defer sink.Close(context.Background())
	_, err = New(Config{Directory: directory}, logger.Warn)
	assert.Error(t, err)
	assert.Equal(t, sink, FromContext(ContextWithSink(t.Context(), sink)))
	assert.Equal(t, (*Sink)(nil), FromContext(t.Context()))

	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for i := range 100 {
				sink.Record(Event{PURL: testPURL, PackageRedacted: i%2 == 0, ActorType: "untrusted", HTTPStatus: 200,
					PolicyMode: "audit", PolicyAction: "allow", PolicyVerdict: "allow", ResponseSource: "origin"})
			}
		})
	}
	workers.Wait()
	assert.NoError(t, sink.Close(context.Background()))
	assert.NoError(t, sink.Close(context.Background()))
	files, err := filepath.Glob(filepath.Join(directory, "*.ndjson"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(files))
	file, err := os.Open(files[0])
	assert.NoError(t, err)
	defer file.Close()
	info, err := file.Stat()
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		assert.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		assert.Equal(t, 1, event.SchemaVersion)
		assert.Equal(t, "unknown", event.ActorType)
		assert.False(t, event.Timestamp.IsZero())
		_, err := uuid.Parse(event.EventID)
		assert.NoError(t, err)
		assert.False(t, seen[event.EventID])
		seen[event.EventID] = true
		if event.PackageRedacted {
			assert.Equal(t, "", event.PURL)
		} else {
			assert.Equal(t, testPURL, event.PURL)
		}
	}
	assert.NoError(t, scanner.Err())
	assert.Equal(t, 800, len(seen))
	reopened, err := New(Config{Directory: directory}, logger.Warn)
	assert.NoError(t, err)
	assert.NoError(t, reopened.Close(context.Background()))
}

func TestWriterRejectsUnsafeDirectory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, directory := range []string{"", "relative"} {
		_, err := New(Config{Directory: directory}, logger.Warn)
		assert.Error(t, err)
	}
	directory := t.TempDir()
	assert.NoError(t, os.Chmod(directory, 0755))
	_, err := New(Config{Directory: directory}, logger.Warn)
	assert.Error(t, err)
	link := filepath.Join(t.TempDir(), "symlink")
	assert.NoError(t, os.Symlink(directory, link))
	_, err = New(Config{Directory: link}, logger.Warn)
	assert.Error(t, err)
}

func TestWriterOverflowIsNonblockingAndReported(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
	counter, err := provider.Meter("test").Int64Counter("events")
	assert.NoError(t, err)
	var logs bytes.Buffer
	sink := &Sink{queue: make(chan []byte, 1), events: counter, warn: slog.New(slog.NewTextHandler(&logs, nil)).Warn}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range 10 {
			sink.Record(Event{PURL: testPURL})
		}
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Record blocked on a full queue")
	}
	sink.Record(Event{PURL: strings.Repeat("x", maxRecordSize)})
	sink.Record(Event{PolicyDurationMS: math.NaN()})
	var data metricdata.ResourceMetrics
	assert.NoError(t, reader.Collect(t.Context(), &data))
	counts := map[string]int64{}
	for _, point := range data.ScopeMetrics[0].Metrics[0].Data.(metricdata.Sum[int64]).DataPoints {
		counts[point.Attributes.ToSlice()[0].Value.AsString()] = point.Value
	}
	assert.Equal(t, map[string]int64{"dropped_queue_full": 9, "dropped_invalid": 2}, counts)
	sink.report(false)
	sink.drop("write_error")
	sink.report(false)
	assert.Equal(t, 1, strings.Count(logs.String(), "Package audit delivery"))
	sink.report(true)
	assert.Equal(t, 2, strings.Count(logs.String(), "Package audit delivery"))
}

func testWriter(t *testing.T, limit int) (*Sink, *sdkmetric.ManualReader) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	assert.NoError(t, err)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("test")
	events, err := meter.Int64Counter("events")
	assert.NoError(t, err)
	evictions, err := meter.Int64Counter("evictions")
	assert.NoError(t, err)
	syncErrors, err := meter.Int64Counter("sync_errors")
	assert.NoError(t, err)
	retentionErrors, err := meter.Int64Counter("retention_errors")
	assert.NoError(t, err)
	shutdownTimeouts, err := meter.Int64Counter("shutdown_timeouts")
	assert.NoError(t, err)
	lock, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	assert.NoError(t, err)
	sink := &Sink{root: root, lock: lock, fileSize: 20, fileLimit: limit,
		queue: make(chan []byte, queueCapacity), done: make(chan struct{}), stop: make(chan struct{}),
		events: events, evictions: evictions, syncErrors: syncErrors, retentionErrors: retentionErrors,
		shutdownTimeouts: shutdownTimeouts, warn: slog.New(slog.NewTextHandler(io.Discard, nil)).Warn}
	t.Cleanup(func() {
		_ = sink.closeFile()
		_ = lock.Close()
		_ = root.Close()
		assert.NoError(t, provider.Shutdown(context.Background()))
	})
	return sink, reader
}

func metricCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var data metricdata.ResourceMetrics
	assert.NoError(t, reader.Collect(t.Context(), &data))
	counts := map[string]int64{}
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			for _, point := range metric.Data.(metricdata.Sum[int64]).DataPoints {
				key := metric.Name
				if attrs := point.Attributes.ToSlice(); len(attrs) != 0 {
					key += ":" + attrs[0].Value.AsString()
				}
				counts[key] += point.Value
			}
		}
	}
	return counts
}

const testRecord = "{\"test\":1}\n"

func TestWriterRotationRetentionAndWriteFailure(t *testing.T) {
	sink, _ := testWriter(t, 2)
	assert.NoError(t, sink.rotate())
	firstName := sink.name
	for range 5 {
		assert.NoError(t, sink.write([]byte(testRecord)))
	}
	assert.NoError(t, sink.closeFile())
	assert.Equal(t, int64(3), sink.evicted.Load())
	assert.Equal(t, 2, len(sink.files))
	_, err := sink.root.Stat(firstName)
	assert.True(t, os.IsNotExist(err))
	for _, name := range sink.files {
		info, err := sink.root.Stat(name)
		assert.NoError(t, err)
		assert.True(t, info.Size() <= sink.fileSize)
	}
}

func TestPersistentWriteFailurePreservesRetainedHistory(t *testing.T) {
	sink, _ := testWriter(t, 3)
	for range 3 {
		assert.NoError(t, sink.write([]byte(testRecord)))
	}
	healthy := append([]string(nil), sink.files...)
	assert.NoError(t, sink.rotate())
	assert.NoError(t, sink.file.Close())
	var err error
	sink.file, err = sink.root.Open(sink.name)
	assert.NoError(t, err)
	failedFile := sink.file
	for range 6 {
		assert.Error(t, sink.write([]byte(testRecord)))
	}
	assert.Equal(t, healthy, sink.files)
	assert.True(t, failedFile == sink.file)
	assert.Equal(t, int64(0), sink.evicted.Load())
	for _, name := range healthy {
		data, err := sink.root.ReadFile(name)
		assert.NoError(t, err)
		assert.Equal(t, testRecord, string(data))
	}
	assert.NoError(t, sink.file.Close())
	sink.file, err = sink.root.OpenFile(sink.name, os.O_RDWR, 0600)
	assert.NoError(t, err)
	_, err = sink.file.WriteAt([]byte("partial abandoned record with a longer tail"), 0)
	assert.NoError(t, err)
	assert.NoError(t, sink.write([]byte(testRecord)))
	assert.Equal(t, int64(1), sink.evicted.Load())
	data, err := sink.root.ReadFile(sink.name)
	assert.NoError(t, err)
	assert.Equal(t, testRecord, string(data))
}

func TestRetentionFailureBlocksGrowthUntilRecovery(t *testing.T) {
	sink, reader := testWriter(t, 1)
	assert.NoError(t, sink.write([]byte(testRecord)))
	oldest := sink.name
	assert.NoError(t, sink.closeFile())
	assert.NoError(t, sink.root.Rename(oldest, "retained-record"))
	assert.NoError(t, sink.root.Mkdir(oldest, 0700))
	assert.NoError(t, sink.root.WriteFile(filepath.Join(oldest, "block-removal"), []byte(testRecord), 0600))
	assert.NoError(t, sink.write([]byte(testRecord)))
	assert.Equal(t, 2, len(sink.files))
	assert.Error(t, sink.write([]byte(testRecord)))
	assert.Equal(t, uint64(2), sink.sequence)
	assert.Equal(t, int64(2), metricCounts(t, reader)["retention_errors"])
	assert.NoError(t, sink.root.Remove(filepath.Join(oldest, "block-removal")))
	assert.NoError(t, sink.root.Remove(oldest))
	assert.NoError(t, sink.root.Rename("retained-record", oldest))
	assert.NoError(t, sink.write([]byte(testRecord)))
	assert.Equal(t, 1, len(sink.files))
	data, err := sink.root.ReadFile(sink.name)
	assert.NoError(t, err)
	assert.Equal(t, testRecord, string(data))
}

func TestRestartOrderingAndMissingFiles(t *testing.T) {
	sink, reader := testWriter(t, 3)
	for range 3 {
		assert.NoError(t, sink.write([]byte(testRecord)))
	}
	healthy := append([]string(nil), sink.files...)
	assert.NoError(t, sink.closeFile())
	// File timestamps deliberately run backwards; sequence order survives restart independently of the clock.
	for i, name := range healthy {
		stamp := time.Unix(int64(100-i), 0)
		assert.NoError(t, sink.root.Chtimes(name, stamp, stamp))
	}
	sink.files, sink.sequence = nil, 0
	assert.NoError(t, sink.loadFiles())
	assert.Equal(t, healthy, sink.files)
	assert.Equal(t, uint64(3), sink.sequence)
	assert.NoError(t, sink.write([]byte(testRecord)))
	assert.Equal(t, uint64(4), sink.sequence)
	_, err := sink.root.Stat(healthy[0])
	assert.True(t, os.IsNotExist(err))
	assert.NoError(t, sink.root.Remove(sink.files[1]))
	assert.NoError(t, sink.write([]byte(testRecord)))
	assert.Equal(t, int64(1), metricCounts(t, reader)["evictions"])
	_, err = sink.root.Stat(healthy[1])
	assert.NoError(t, err)
}

func TestCloseDeadlineStopsDelayedWorkerAndCountsDrops(t *testing.T) {
	sink, reader := testWriter(t, 3)
	for range queueCapacity {
		sink.Record(Event{PURL: testPURL})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	closed := make(chan error, 1)
	go func() { closed <- sink.Close(ctx) }()
	select {
	case err := <-closed:
		assert.True(t, errors.Is(err, context.DeadlineExceeded))
	case <-time.After(time.Second):
		t.Fatal("Close exceeded its deadline waiting for a stalled worker")
	}
	sink.Record(Event{PURL: testPURL})
	// The worker resumes only after Close has returned, modeling a disk syscall that outlives its caller.
	go sink.run()
	select {
	case <-sink.done:
	case <-time.After(time.Second):
		t.Fatal("worker drained abandoned records instead of stopping")
	}
	assert.Equal(t, map[string]int64{"shutdown_timeouts": 1, "events:dropped_closed": 1,
		"events:dropped_shutdown_timeout": queueCapacity}, metricCounts(t, reader))
	assert.Error(t, sink.Close(context.Background()))
}

func TestRestartRemovesOnlyEmptySegments(t *testing.T) {
	sink, reader := testWriter(t, 3)
	assert.NoError(t, sink.write([]byte(testRecord)))
	healthy := sink.name
	assert.NoError(t, sink.rotate())
	empty := sink.name
	assert.NoError(t, sink.file.Close())
	sink.file = nil // Simulate a crash leaving the just-created empty segment behind.
	sink.files, sink.sequence = nil, 0
	assert.NoError(t, sink.loadFiles())
	assert.Equal(t, []string{healthy}, sink.files)
	assert.Equal(t, uint64(2), sink.sequence)
	_, err := sink.root.Stat(empty)
	assert.True(t, os.IsNotExist(err))
	data, err := sink.root.ReadFile(healthy)
	assert.NoError(t, err)
	assert.Equal(t, testRecord, string(data))
	assert.Equal(t, int64(0), metricCounts(t, reader)["evictions"])
}

func TestWriteFailureBackoffIsInterruptible(t *testing.T) {
	sink, reader := testWriter(t, 3)
	assert.NoError(t, sink.rotate())
	assert.NoError(t, sink.file.Close())
	var err error
	sink.file, err = sink.root.Open(sink.name)
	assert.NoError(t, err)
	for range 3 {
		sink.queue <- []byte(testRecord)
	}
	go sink.run()
	deadline := time.After(time.Second)
	for len(sink.queue) == 3 {
		select {
		case <-deadline:
			t.Fatal("worker never attempted its first write")
		case <-time.After(time.Millisecond):
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	assert.True(t, errors.Is(sink.Close(ctx), context.DeadlineExceeded))
	select {
	case <-sink.done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not interrupt disk-failure backoff")
	}
	counts := metricCounts(t, reader)
	assert.Equal(t, int64(1), counts["events:dropped_write_error"])
	assert.Equal(t, int64(2), counts["events:dropped_shutdown_timeout"])
}

func TestSyncFailureAndNonRegularSegment(t *testing.T) {
	sink, reader := testWriter(t, 3)
	assert.NoError(t, sink.rotate())
	assert.NoError(t, sink.file.Close())
	assert.Error(t, sink.syncFile())
	assert.Equal(t, int64(1), metricCounts(t, reader)["sync_errors"])
	assert.NoError(t, sink.root.Mkdir(filePrefix+"unexpected.ndjson", 0700))
	assert.Error(t, sink.loadFiles())
}

func TestRecordRacesCloseSafely(t *testing.T) {
	sink, err := New(Config{Directory: filepath.Join(t.TempDir(), "audit")}, slog.New(slog.NewTextHandler(io.Discard, nil)).Warn)
	assert.NoError(t, err)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				sink.Record(Event{PURL: testPURL})
			}
		})
	}
	workers.Go(func() { assert.NoError(t, sink.Close(context.Background())) })
	workers.Wait()
	assert.NoError(t, sink.Close(context.Background()))
}
