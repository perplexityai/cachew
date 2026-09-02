package cache //nolint:testpackage // White-box coverage injects blocked disk lifecycle operations.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/logging"
)

const diskIsolationTestTimeout = 20 * time.Millisecond

func waitForDiskSlots(t *testing.T, isolation *diskReadIsolation) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(isolation.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, 0, len(isolation.slots))
}

func TestDiskReadIsolationTimesOutBlockedStat(t *testing.T) {
	isolation := newDiskReadIsolation(t.Context(), 1, diskIsolationTestTimeout, time.Second)
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

	close(release)
	waitForDiskSlots(t, isolation)
}

func TestDiskReadIsolationTimesOutBlockedOpen(t *testing.T) {
	isolation := newDiskReadIsolation(t.Context(), 1, diskIsolationTestTimeout, time.Second)
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
	isolation := newDiskReadIsolation(t.Context(), 2, time.Hour, time.Hour)
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
	_, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		extraOpen.Store(true)
		return nil, nil, nil
	})
	assert.IsError(t, err, ErrTierUnavailable)
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
	isolation := newDiskReadIsolation(t.Context(), 1, time.Second, diskIsolationTestTimeout)
	source := newReadBlockingCloser()
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return source, http.Header{}, nil
	})
	assert.NoError(t, err)
	<-source.readStarted

	_, err = reader.Read(make([]byte, 1))
	assert.IsError(t, err, ErrTierUnavailable)
	waitForDiskSlots(t, isolation)
	assert.NoError(t, reader.Close())
}

type closeBlockingReader struct {
	closeStarted chan struct{}
	releaseClose chan struct{}
	closeOnce    sync.Once
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
	isolation := newDiskReadIsolation(t.Context(), 1, time.Second, diskIsolationTestTimeout)
	source := &lateReadCloser{readStarted: make(chan struct{}), releaseRead: make(chan struct{})}
	reader, _, err := isolation.open(t.Context(), func(context.Context) (io.ReadCloser, http.Header, error) {
		return source, http.Header{}, nil
	})
	assert.NoError(t, err)
	<-source.readStarted

	destination := []byte{0}
	_, err = reader.Read(destination)
	assert.IsError(t, err, ErrTierUnavailable)
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

func TestDiskReadIsolationBoundsBlockedReaderClose(t *testing.T) {
	isolation := newDiskReadIsolation(t.Context(), 1, diskIsolationTestTimeout, time.Second)
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
	assert.Equal(t, 1, len(isolation.slots))

	close(source.releaseClose)
	waitForDiskSlots(t, isolation)
}

type unavailableReadCache struct {
	Cache
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

func TestTieredReadSurfacesUnavailableAuthoritativeTier(t *testing.T) {
	tiered := Tiered{caches: []Cache{NoOpCache(), unavailableReadCache{Cache: NoOpCache()}}}
	key := NewKey("authoritative-unavailable")

	_, err := tiered.Stat(t.Context(), key)
	assert.IsError(t, err, ErrTierUnavailable)
	_, _, err = tiered.Open(t.Context(), key)
	assert.IsError(t, err, ErrTierUnavailable)
}
