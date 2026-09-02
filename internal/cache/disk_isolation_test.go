package cache //nolint:testpackage // White-box coverage injects blocked disk lifecycle operations.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/logging"
)

const diskIsolationTestTimeout = 20 * time.Millisecond

type recordedDiskReadEvent struct {
	event     diskReadEvent
	operation diskReadOperation
	tier      BackendType
}

type recordingDiskMetrics struct {
	mu     sync.Mutex
	events []recordedDiskReadEvent
}

func (r *recordingDiskMetrics) record(
	_ context.Context,
	event diskReadEvent,
	operation diskReadOperation,
	tier BackendType,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, recordedDiskReadEvent{event: event, operation: operation, tier: tier})
}

func (r *recordingDiskMetrics) snapshot() []recordedDiskReadEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedDiskReadEvent(nil), r.events...)
}

func waitForDiskSlots(t *testing.T, isolation *diskReadIsolation) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(isolation.readSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, 0, len(isolation.readSlots))
}

func waitForDiskCloseSlots(t *testing.T, isolation *diskReadIsolation) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(isolation.closeSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, 0, len(isolation.closeSlots))
}

func waitForDiskReaderSlots(t *testing.T, isolation *diskReadIsolation) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(isolation.readerSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, 0, len(isolation.readerSlots))
}

func newTestDiskReadIsolation(
	t *testing.T,
	concurrency int,
	operationTimeout time.Duration,
	readIdleTimeout time.Duration,
) *diskReadIsolation {
	t.Helper()
	return newDiskReadIsolation(t.Context(), DiskConfig{
		ReadConcurrency:  concurrency,
		OpenReaderLimit:  defaultDiskOpenReaderLimit,
		OperationTimeout: operationTimeout,
		ReadIdleTimeout:  readIdleTimeout,
	})
}

func TestDiskReadIsolationTimesOutBlockedStat(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, diskIsolationTestTimeout, time.Second)
	metrics := &recordingDiskMetrics{}
	isolation.metrics = metrics
	started := make(chan struct{})
	release := make(chan struct{})
	var attempts atomic.Int64

	begin := time.Now()
	_, err := isolation.stat(t.Context(), func(context.Context) (http.Header, error) {
		attempts.Add(1)
		close(started)
		<-release
		return http.Header{}, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
	assert.True(t, time.Since(begin) < time.Second)
	<-started

	_, err = isolation.stat(t.Context(), func(context.Context) (http.Header, error) {
		attempts.Add(1)
		return http.Header{}, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
	assert.Equal(t, int64(1), attempts.Load())
	assert.Equal(t, []recordedDiskReadEvent{{
		event: diskReadEventBreakerTrip, operation: diskReadOperationStat, tier: backendDisk,
	}}, metrics.snapshot())

	close(release)
	waitForDiskSlots(t, isolation)
}

func TestDiskReadIsolationTimesOutBlockedOpen(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, diskIsolationTestTimeout, time.Second)
	started := make(chan struct{})
	release := make(chan struct{})

	_, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		close(started)
		<-release
		return io.NopCloser(nil), http.Header{}, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
	<-started
	close(release)
	waitForDiskSlots(t, isolation)
}

func TestDiskReadIsolationBoundsBlockedOpen(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 2, time.Hour, time.Hour)
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	results := make(chan error, 2)
	contexts := make([]context.CancelFunc, 0, 2)
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		contexts = append(contexts, cancel)
		go func() {
			_, _, err := isolation.open(ctx, func(context.Context) (io.ReadCloser, http.Header, error) {
				started <- struct{}{}
				<-release
				return nil, nil, nil
			})
			results <- err
		}()
	}
	<-started
	<-started

	var extraOpen atomic.Bool
	waitCtx, cancelWait := context.WithTimeout(t.Context(), diskIsolationTestTimeout)
	defer cancelWait()
	_, _, err := isolation.open(waitCtx, func(context.Context) (io.ReadCloser, http.Header, error) {
		extraOpen.Store(true)
		return nil, nil, nil
	})
	assert.IsError(t, err, context.DeadlineExceeded)
	assert.False(t, extraOpen.Load())

	for _, cancel := range contexts {
		cancel()
	}
	for range 2 {
		assert.IsError(t, <-results, context.Canceled)
	}
	close(release)
	waitForDiskSlots(t, isolation)
}

func TestDiskReadIsolationDoesNotHoldSlotAcrossReaderLifetime(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, time.Second, time.Second)
	readers := make([]io.ReadCloser, 0, 65)
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return io.NopCloser(strings.NewReader("healthy")), http.Header{}, nil
	})
	assert.NoError(t, err)
	readers = append(readers, reader)
	buffer := make([]byte, 1)
	_, err = reader.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, byte('h'), buffer[0])

	for range 64 {
		openedReader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
			return io.NopCloser(strings.NewReader("healthy")), http.Header{}, nil
		})
		assert.NoError(t, err)
		readers = append(readers, openedReader)
	}
	assert.Equal(t, 0, len(isolation.readSlots))
	for _, reader := range readers {
		assert.NoError(t, reader.Close())
	}
}

func TestDiskReadIsolationIgnoresConsumerPause(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, time.Second, diskIsolationTestTimeout)
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return io.NopCloser(strings.NewReader("ab")), http.Header{}, nil
	})
	assert.NoError(t, err)

	buffer := make([]byte, 1)
	n, err := reader.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte('a'), buffer[0])
	time.Sleep(2 * diskIsolationTestTimeout)
	n, err = reader.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte('b'), buffer[0])
	assert.NoError(t, reader.Close())
}

func TestIsolatedDiskReaderExposesUntouchedFile(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, time.Second, time.Second)
	path := filepath.Join(t.TempDir(), "artifact")
	assert.NoError(t, os.WriteFile(path, []byte("artifact"), 0600))
	file, err := os.Open(path)
	assert.NoError(t, err)
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return file, http.Header{}, nil
	})
	assert.NoError(t, err)
	isolationReader, ok := reader.(*isolatedDiskReader)
	assert.True(t, ok)
	assert.Equal(t, file, isolationReader.RawFile())
	assert.NoError(t, reader.Close())
}

type readBlockingCloser struct {
	readStarted chan struct{}
	releaseRead chan struct{}
	closeOnce   sync.Once
}

func newReadBlockingCloser() *readBlockingCloser {
	return &readBlockingCloser{readStarted: make(chan struct{}), releaseRead: make(chan struct{})}
}

func (r *readBlockingCloser) Read(_ []byte) (int, error) {
	close(r.readStarted)
	<-r.releaseRead
	return 0, context.Canceled
}

func (r *readBlockingCloser) Close() error {
	r.closeOnce.Do(func() { close(r.releaseRead) })
	return nil
}

func TestDiskReadIsolationTimesOutBlockedBodyRead(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, time.Second, diskIsolationTestTimeout)
	source := newReadBlockingCloser()
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return source, http.Header{}, nil
	})
	assert.NoError(t, err)

	_, err = reader.Read(make([]byte, 1))
	assert.IsError(t, err, ErrTierUnavailable)
	<-source.readStarted
	waitForDiskSlots(t, isolation)
	assert.NoError(t, reader.Close())
}

type closeBlockingReader struct {
	closeStarted chan struct{}
	releaseClose chan struct{}
	closeOnce    sync.Once
	releaseOnce  sync.Once
}

type lateReadCloser struct {
	readStarted chan struct{}
	releaseRead chan struct{}
}

func (r *lateReadCloser) Read(p []byte) (int, error) {
	close(r.readStarted)
	<-r.releaseRead
	p[0] = 0xff
	return 1, nil
}

func (r *lateReadCloser) Close() error {
	return nil
}

func TestDiskReadIsolationDiscardsLateReadAfterTimeout(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, time.Second, diskIsolationTestTimeout)
	source := &lateReadCloser{readStarted: make(chan struct{}), releaseRead: make(chan struct{})}
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return source, http.Header{}, nil
	})
	assert.NoError(t, err)

	destination := []byte{0}
	_, err = reader.Read(destination)
	assert.IsError(t, err, ErrTierUnavailable)
	<-source.readStarted
	close(source.releaseRead)
	waitForDiskSlots(t, isolation)
	assert.Equal(t, byte(0), destination[0])
	_, err = reader.Read(destination)
	assert.IsError(t, err, ErrTierUnavailable)
}

func newCloseBlockingReader() *closeBlockingReader {
	return &closeBlockingReader{closeStarted: make(chan struct{}), releaseClose: make(chan struct{})}
}

func (r *closeBlockingReader) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (r *closeBlockingReader) Close() error {
	r.closeOnce.Do(func() {
		close(r.closeStarted)
		<-r.releaseClose
	})
	return nil
}

func (r *closeBlockingReader) release() {
	r.releaseOnce.Do(func() { close(r.releaseClose) })
}

func TestDiskReadIsolationBoundsBlockedReaderClose(t *testing.T) {
	isolation := newTestDiskReadIsolation(t, 1, diskIsolationTestTimeout, time.Second)
	source := newCloseBlockingReader()
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return source, http.Header{}, nil
	})
	assert.NoError(t, err)

	_, err = reader.Read(make([]byte, 1))
	assert.IsError(t, err, io.EOF)
	<-source.closeStarted
	err = reader.Close()
	assert.IsError(t, err, ErrTierUnavailable)
	assert.Equal(t, 1, len(isolation.closeSlots))

	source.release()
	waitForDiskCloseSlots(t, isolation)
}

func TestDiskReadIsolationBoundsReadersAwaitingClose(t *testing.T) {
	isolation := newDiskReadIsolation(t.Context(), DiskConfig{
		ReadConcurrency:  1,
		OpenReaderLimit:  3,
		OperationTimeout: diskIsolationTestTimeout,
		ReadIdleTimeout:  time.Second,
	})
	sources := []*closeBlockingReader{
		newCloseBlockingReader(),
		newCloseBlockingReader(),
		newCloseBlockingReader(),
	}
	for _, source := range sources {
		t.Cleanup(source.release)
		isolation.degradedUntil.Store(0)
		reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
			return source, http.Header{}, nil
		})
		assert.NoError(t, err)
		err = reader.Close()
		assert.IsError(t, err, ErrTierUnavailable)
	}

	assert.Equal(t, 3, len(isolation.readerSlots))
	assert.Equal(t, 1, len(isolation.closeSlots))
	for _, source := range sources[1:] {
		select {
		case <-source.closeStarted:
			t.Fatal("queued reader Close started without an available close slot")
		default:
		}
	}

	isolation.degradedUntil.Store(0)
	var extraOpen atomic.Bool
	_, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		extraOpen.Store(true)
		return io.NopCloser(strings.NewReader("extra")), http.Header{}, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
	assert.False(t, extraOpen.Load())

	for _, source := range sources {
		source.release()
	}
	waitForDiskReaderSlots(t, isolation)
	waitForDiskCloseSlots(t, isolation)

	isolation.degradedUntil.Store(0)
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return io.NopCloser(strings.NewReader("healthy")), http.Header{}, nil
	})
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
}

func TestDiskReadIsolationBoundsLateOpenCleanup(t *testing.T) {
	isolation := newDiskReadIsolation(t.Context(), DiskConfig{
		ReadConcurrency:  1,
		OpenReaderLimit:  1,
		OperationTimeout: diskIsolationTestTimeout,
		ReadIdleTimeout:  time.Second,
	})
	source := newCloseBlockingReader()
	t.Cleanup(source.release)
	openStarted := make(chan struct{})
	releaseOpen := make(chan struct{})
	var releaseOpenOnce sync.Once
	releaseBlockedOpen := func() { releaseOpenOnce.Do(func() { close(releaseOpen) }) }
	t.Cleanup(releaseBlockedOpen)

	_, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		close(openStarted)
		<-releaseOpen
		return source, http.Header{}, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
	<-openStarted
	assert.Equal(t, 1, len(isolation.readerSlots))

	isolation.degradedUntil.Store(0)
	var extraOpen atomic.Bool
	_, _, err = isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		extraOpen.Store(true)
		return io.NopCloser(strings.NewReader("extra")), http.Header{}, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
	assert.False(t, extraOpen.Load())

	releaseBlockedOpen()
	select {
	case <-source.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("late Open reader was not closed")
	}
	assert.Equal(t, 1, len(isolation.readerSlots))
	source.release()
	waitForDiskReaderSlots(t, isolation)
}

func TestDiskReadIsolationDrainsReadersOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	isolation := newDiskReadIsolation(ctx, DiskConfig{
		ReadConcurrency:  1,
		OpenReaderLimit:  1,
		OperationTimeout: time.Second,
		ReadIdleTimeout:  time.Second,
	})
	_, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return io.NopCloser(strings.NewReader("healthy")), http.Header{}, nil
	})
	assert.NoError(t, err)

	cancel()
	select {
	case <-isolation.dispatcherDone:
	case <-time.After(time.Second):
		t.Fatal("close dispatcher did not drain open readers on shutdown")
	}
	assert.Equal(t, 0, len(isolation.readerSlots))
}

type unavailableReadCache struct {
	Cache
}

type errorReadCache struct {
	Cache
	err error
}

func (c errorReadCache) Stat(context.Context, Key, ...Option) (http.Header, error) {
	return nil, c.err
}

func (c errorReadCache) Open(context.Context, Key, ...Option) (io.ReadCloser, http.Header, error) {
	return nil, nil, c.err
}

func (c unavailableReadCache) Stat(context.Context, Key, ...Option) (http.Header, error) {
	return nil, diskTierUnavailable("test tier unavailable")
}

func (c unavailableReadCache) Open(context.Context, Key, ...Option) (io.ReadCloser, http.Header, error) {
	return nil, nil, diskTierUnavailable("test tier unavailable")
}

func TestTieredReadBypassesUnavailableLocalTier(t *testing.T) {
	lower := newMemoryTestCache(t)
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	key := NewKey("tier-bypass")
	body := []byte("from deeper tier")
	writeMemoryTestEntry(t, lower, key, body, time.Hour)
	tiered := Tiered{caches: []Cache{unavailableReadCache{Cache: NoOpCache()}, lower}}

	headers, err := tiered.Stat(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, strconv.Itoa(len(body)), headers.Get("Content-Length"))
	reader, _, err := tiered.Open(ctx, key)
	assert.NoError(t, err)
	actual, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, body, actual)
}

func TestTieredReadTreatsUnavailableAuthoritativeTierAsMiss(t *testing.T) {
	metrics := &recordingDiskMetrics{}
	previousMetrics := defaultDiskMetrics
	defaultDiskMetrics = metrics
	t.Cleanup(func() { defaultDiskMetrics = previousMetrics })
	tiered := Tiered{caches: []Cache{NoOpCache(), unavailableReadCache{Cache: NoOpCache()}}}
	key := NewKey("authoritative-unavailable")

	_, err := tiered.Stat(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
	_, _, err = tiered.Open(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)

	authoritative := authoritativeCache{Cache: unavailableReadCache{Cache: NoOpCache()}}
	_, err = authoritative.Stat(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
	_, _, err = authoritative.Open(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
	assert.Equal(t, []recordedDiskReadEvent{
		{event: diskReadEventAuthoritativeMiss, operation: diskReadOperationStat, tier: backendUnknown},
		{event: diskReadEventAuthoritativeMiss, operation: diskReadOperationOpen, tier: backendUnknown},
		{event: diskReadEventAuthoritativeMiss, operation: diskReadOperationStat, tier: backendUnknown},
		{event: diskReadEventAuthoritativeMiss, operation: diskReadOperationOpen, tier: backendUnknown},
	}, metrics.snapshot())
}

func TestTieredUnavailableAuthoritativeTierPreservesDeferredError(t *testing.T) {
	hardErr := errors.New("deferred tier failure")
	tiered := Tiered{caches: []Cache{
		errorReadCache{Cache: NoOpCache(), err: ErrPreconditionFailed},
		errorReadCache{Cache: NoOpCache(), err: hardErr},
		unavailableReadCache{Cache: NoOpCache()},
	}}
	key := NewKey("authoritative-unavailable-after-error")

	_, err := tiered.Stat(t.Context(), key)
	assert.IsError(t, err, hardErr)
	assert.False(t, errors.Is(err, os.ErrNotExist))
	_, _, err = tiered.Open(t.Context(), key)
	assert.IsError(t, err, hardErr)
	assert.False(t, errors.Is(err, os.ErrNotExist))
}
