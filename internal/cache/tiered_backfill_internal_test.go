package cache

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/logging"
)

func backfillTestContext(t *testing.T) context.Context {
	t.Helper()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	return ctx
}

func TestTieredBackfillLeasesAreVersionAwareAndConcurrencyBounded(t *testing.T) {
	ctx := backfillTestContext(t)
	manager := newTieredBackfillsWithLimits(ctx, 2, 1024)
	defer manager.close()
	key := NewKey("version-aware-backfill")

	first, ok := manager.start(ctx, tieredBackfillKey{namespace: "git", key: key, etag: "v1"})
	assert.True(t, ok)
	_, ok = manager.start(ctx, tieredBackfillKey{namespace: "git", key: key, etag: "v1"})
	assert.False(t, ok)
	second, ok := manager.start(ctx, tieredBackfillKey{namespace: "git", key: key, etag: "v2"})
	assert.True(t, ok)
	_, ok = manager.start(ctx, tieredBackfillKey{namespace: "gomod", key: key, etag: "v1"})
	assert.False(t, ok)

	second.finish()
	third, ok := manager.start(ctx, tieredBackfillKey{namespace: "gomod", key: key, etag: "v1"})
	assert.True(t, ok)
	first.finish()
	third.finish()

	retry, ok := manager.start(ctx, tieredBackfillKey{namespace: "git", key: key, etag: "v1"})
	assert.True(t, ok)
	retry.finish()
}

func TestTieredBackfillAbandonsAtAggregateBufferLimit(t *testing.T) {
	ctx := backfillTestContext(t)
	manager := newTieredBackfillsWithLimits(ctx, 1, 4)
	lease, ok := manager.start(ctx, tieredBackfillKey{key: NewKey("bounded-buffer"), etag: "v1"})
	assert.True(t, ok)
	createStarted := make(chan struct{})
	reader := newBackfillReadCloser(
		io.NopCloser(bytes.NewReader([]byte("abcdefgh"))),
		func(ctx context.Context) (Writer, error) {
			close(createStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		lease,
	)
	<-createStarted

	var body bytes.Buffer
	buf := make([]byte, 4)
	n, err := reader.Read(buf)
	assert.NoError(t, err)
	body.Write(buf[:n])
	assert.Equal(t, int64(4), manager.buffered.Load())
	n, err = reader.Read(buf)
	assert.NoError(t, err)
	body.Write(buf[:n])
	_, err = reader.Read(buf)
	assert.IsError(t, err, io.EOF)
	assert.NoError(t, reader.Close())

	manager.close()
	assert.Equal(t, "abcdefgh", body.String())
	assert.Equal(t, int64(0), manager.buffered.Load())
}

type blockingCommitWriter struct {
	bytes.Buffer
	started chan struct{}
	release chan struct{}
	once    sync.Once
	aborted atomic.Bool
}

func (w *blockingCommitWriter) Close() error {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return nil
}

func (w *blockingCommitWriter) Abort(error) error {
	w.aborted.Store(true)
	return nil
}

func TestTieredBackfillCommitDoesNotDelayReaderClose(t *testing.T) {
	ctx := backfillTestContext(t)
	manager := newTieredBackfillsWithLimits(ctx, 1, 1024)
	defer manager.close()
	lease, ok := manager.start(ctx, tieredBackfillKey{key: NewKey("nonblocking-close"), etag: "v1"})
	assert.True(t, ok)
	w := &blockingCommitWriter{started: make(chan struct{}), release: make(chan struct{})}
	reader := newBackfillReadCloser(
		io.NopCloser(bytes.NewReader([]byte("body"))),
		func(context.Context) (Writer, error) { return w, nil },
		lease,
	)

	body, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, []byte("body"), body)
	closed := make(chan error, 1)
	go func() { closed <- reader.Close() }()
	select {
	case err := <-closed:
		assert.NoError(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cache writer commit delayed the source reader")
	}
	select {
	case <-w.started:
	case <-time.After(2 * time.Second):
		t.Fatal("backfill writer did not start committing")
	}
	assert.False(t, w.aborted.Load())
	close(w.release)
}

func TestTieredBackfillManagerCloseCancelsOutstandingFill(t *testing.T) {
	ctx := backfillTestContext(t)
	manager := newTieredBackfillsWithLimits(ctx, 1, 1024)
	lease, ok := manager.start(ctx, tieredBackfillKey{key: NewKey("shutdown"), etag: "v1"})
	assert.True(t, ok)
	createStarted := make(chan struct{})
	_ = newBackfillReadCloser(
		io.NopCloser(bytes.NewReader([]byte("body"))),
		func(ctx context.Context) (Writer, error) {
			close(createStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		lease,
	)
	<-createStarted

	closed := make(chan struct{})
	go func() {
		manager.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("backfill manager did not drain after cancellation")
	}
}
