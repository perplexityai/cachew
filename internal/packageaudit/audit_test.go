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
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const testPURL = "pkg:npm/example@1.2.3"

func TestWriterDrainsRedactsAndLocks(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "audit")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sink, err := New(Config{Directory: directory}, logger)
	assert.NoError(t, err)
	defer sink.Close()
	_, err = New(Config{Directory: directory}, logger)
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
	assert.NoError(t, sink.Close())
	assert.NoError(t, sink.Close())
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
	reopened, err := New(Config{Directory: directory}, logger)
	assert.NoError(t, err)
	assert.NoError(t, reopened.Close())
}

func TestWriterRejectsUnsafeDirectory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, directory := range []string{"", "relative"} {
		_, err := New(Config{Directory: directory}, logger)
		assert.Error(t, err)
	}
	directory := t.TempDir()
	assert.NoError(t, os.Chmod(directory, 0755))
	_, err := New(Config{Directory: directory}, logger)
	assert.Error(t, err)
	link := filepath.Join(t.TempDir(), "symlink")
	assert.NoError(t, os.Symlink(directory, link))
	_, err = New(Config{Directory: link}, logger)
	assert.Error(t, err)
}

func TestWriterOverflowIsNonblockingAndReported(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
	counter, err := provider.Meter("test").Int64Counter("events")
	assert.NoError(t, err)
	var logs bytes.Buffer
	sink := &Sink{queue: make(chan []byte, 1), events: counter, logger: slog.New(slog.NewTextHandler(&logs, nil))}
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

func TestWriterRotationRetentionAndWriteFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	assert.NoError(t, err)
	defer root.Close()
	meter := otel.Meter("test")
	events, err := meter.Int64Counter("package_audit_test_events")
	assert.NoError(t, err)
	evictions, err := meter.Int64Counter("package_audit_test_evictions")
	assert.NoError(t, err)
	sink := &Sink{root: root, fileSize: 20, fileLimit: 2, events: events, evictions: evictions, syncErrors: events}
	assert.NoError(t, sink.rotate())
	firstName := sink.files[0]
	for range 5 {
		assert.NoError(t, sink.write([]byte("{\"test\":1}\n")))
	}
	assert.NoError(t, sink.closeFile())
	assert.Equal(t, int64(3), sink.evicted.Load())
	assert.Equal(t, 2, len(sink.files))
	_, err = root.Stat(firstName)
	assert.True(t, os.IsNotExist(err))
	for _, name := range sink.files {
		info, err := root.Stat(name)
		assert.NoError(t, err)
		assert.True(t, info.Size() <= sink.fileSize)
	}
	assert.NoError(t, sink.rotate())
	assert.NoError(t, sink.file.Close())
	assert.Error(t, sink.write([]byte("{\"test\":2}\n")))
	assert.Equal(t, (*os.File)(nil), sink.file)
}

func TestRecordRacesCloseSafely(t *testing.T) {
	sink, err := New(Config{Directory: filepath.Join(t.TempDir(), "audit")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.NoError(t, err)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				sink.Record(Event{PURL: testPURL})
			}
		})
	}
	workers.Go(func() { assert.NoError(t, sink.Close()) })
	workers.Wait()
	assert.NoError(t, sink.Close())
}
