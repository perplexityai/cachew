package cache

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/logging"
)

const (
	tieredBackfillMaxConcurrency = 8
	tieredBackfillMaxBufferBytes = 32 << 20
	tieredBackfillBufferSlots    = 128
	tieredBackfillTimeout        = 5 * time.Minute
)

var (
	errBackfillAbandoned = errors.New("tier backfill abandoned")
	errBackfillNilWriter = errors.New("tier backfill cache returned a nil writer")
	errBackfillTimeout   = errors.New("tier backfill timed out")
)

type tieredBackfillKey struct {
	namespace Namespace
	key       Key
	etag      string
}

// tieredBackfills is shared by every namespaced view so its concurrency and
// buffer ceilings apply to the whole tiered cache, not independently to each
// request path. Leases are keyed by source ETag because two representations of
// one logical key must never share a partial fill.
type tieredBackfills struct {
	mu       sync.Mutex
	inflight map[tieredBackfillKey]struct{}
	sem      chan struct{}
	buffered atomic.Int64
	maxBytes int64
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   bool
}

func newTieredBackfills(ctx context.Context) *tieredBackfills {
	return newTieredBackfillsWithLimits(ctx, tieredBackfillMaxConcurrency, tieredBackfillMaxBufferBytes)
}

func newTieredBackfillsWithLimits(ctx context.Context, maxConcurrency int, maxBufferBytes int64) *tieredBackfills {
	backfillCtx, cancel := context.WithCancel(context.WithoutCancel(ctx)) //nolint:gosec // cancel is stored and called in Close
	return &tieredBackfills{
		inflight: map[tieredBackfillKey]struct{}{},
		sem:      make(chan struct{}, maxConcurrency),
		maxBytes: maxBufferBytes,
		ctx:      backfillCtx,
		cancel:   cancel,
	}
}

type tieredBackfillLease struct {
	manager       *tieredBackfills
	key           tieredBackfillKey
	ctx           context.Context
	cancel        context.CancelCauseFunc
	timeoutCancel context.CancelFunc
	once          sync.Once
}

func (b *tieredBackfills) start(reqCtx context.Context, key tieredBackfillKey) (*tieredBackfillLease, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, false
	}
	if _, ok := b.inflight[key]; ok {
		return nil, false
	}
	select {
	case b.sem <- struct{}{}:
	default:
		return nil, false
	}

	ctx := logging.ContextWithLogger(b.ctx, logging.FromContext(reqCtx))
	timeoutCtx, timeoutCancel := context.WithTimeoutCause(ctx, tieredBackfillTimeout, errBackfillTimeout)
	ctx, cancel := context.WithCancelCause(timeoutCtx)
	b.inflight[key] = struct{}{}
	b.wg.Add(1)
	return &tieredBackfillLease{
		manager:       b,
		key:           key,
		ctx:           ctx,
		cancel:        cancel,
		timeoutCancel: timeoutCancel,
	}, true
}

func (b *tieredBackfills) trigger(reqCtx context.Context, key tieredBackfillKey, fill func(context.Context)) {
	lease, ok := b.start(reqCtx, key)
	if !ok {
		return
	}
	go func() {
		defer lease.finish()
		fill(lease.ctx)
	}()
}

func (l *tieredBackfillLease) finish() {
	l.once.Do(func() {
		l.cancel(nil)
		l.timeoutCancel()
		l.manager.mu.Lock()
		delete(l.manager.inflight, l.key)
		l.manager.mu.Unlock()
		<-l.manager.sem
		l.manager.wg.Done()
	})
}

func (b *tieredBackfills) close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.cancel()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

func (b *tieredBackfills) tryReserveBuffer(size int) bool {
	want := int64(size)
	for {
		used := b.buffered.Load()
		if want > b.maxBytes-used {
			return false
		}
		if b.buffered.CompareAndSwap(used, used+want) {
			return true
		}
	}
}

func (b *tieredBackfills) releaseBuffer(size int) {
	b.buffered.Add(-int64(size))
}

type backfillWriterFactory func(context.Context) (Writer, error)

// backfillReadCloser copies source reads to an asynchronously-created cache
// writer. The client path never waits for writer creation, writes, or commit;
// incomplete streams and any resource saturation abort only the optional fill.
type backfillReadCloser struct {
	src       io.ReadCloser
	create    backfillWriterFactory
	lease     *tieredBackfillLease
	chunks    chan []byte
	mu        sync.Mutex
	accepting bool
	eof       bool
	commit    bool
	closeOnce sync.Once
	closeErr  error
}

func newBackfillReadCloser(src io.ReadCloser, create backfillWriterFactory, lease *tieredBackfillLease) *backfillReadCloser {
	b := &backfillReadCloser{
		src:       src,
		create:    create,
		lease:     lease,
		chunks:    make(chan []byte, tieredBackfillBufferSlots),
		accepting: true,
	}
	go b.run()
	return b
}

func (b *backfillReadCloser) run() {
	defer b.lease.finish()
	w, err := b.create(b.lease.ctx)
	if err != nil || w == nil {
		if err == nil {
			err = errBackfillNilWriter
		}
		b.stop(err, false)
		b.drainChunks()
		if w != nil {
			err = errors.Join(err, w.Abort(err))
		}
		if !errors.Is(err, context.Canceled) {
			logging.FromContext(b.lease.ctx).WarnContext(b.lease.ctx, "Tier backfill: failed to create writer", "error", err)
		}
		return
	}

	for {
		select {
		case <-b.lease.ctx.Done():
			cause := context.Cause(b.lease.ctx)
			b.stop(cause, false)
			b.drainChunks()
			if err := w.Abort(cause); err != nil && !errors.Is(err, context.Canceled) {
				logging.FromContext(b.lease.ctx).WarnContext(b.lease.ctx, "Tier backfill: abort failed", "error", err)
			}
			return
		case chunk, ok := <-b.chunks:
			if !ok {
				b.finishWriter(w)
				return
			}
			n, err := w.Write(chunk)
			b.lease.manager.releaseBuffer(len(chunk))
			if err == nil && n != len(chunk) {
				err = io.ErrShortWrite
			}
			if err != nil {
				b.stop(err, false)
				b.drainChunks()
				logging.FromContext(b.lease.ctx).WarnContext(b.lease.ctx, "Tier backfill: write failed", "error", errors.Join(err, w.Abort(err)))
				return
			}
		}
	}
}

func (b *backfillReadCloser) finishWriter(w Writer) {
	b.mu.Lock()
	commit := b.commit
	b.mu.Unlock()
	if commit {
		if err := w.Close(); err != nil {
			logging.FromContext(b.lease.ctx).WarnContext(b.lease.ctx, "Tier backfill: commit failed", "error", err)
		}
		return
	}
	if err := w.Abort(errBackfillAbandoned); err != nil && !errors.Is(err, context.Canceled) {
		logging.FromContext(b.lease.ctx).WarnContext(b.lease.ctx, "Tier backfill: abort failed", "error", err)
	}
}

func (b *backfillReadCloser) drainChunks() {
	for chunk := range b.chunks {
		b.lease.manager.releaseBuffer(len(chunk))
	}
}

func (b *backfillReadCloser) stop(cause error, commit bool) {
	b.mu.Lock()
	if b.accepting {
		b.accepting = false
		b.commit = commit
		close(b.chunks)
	}
	b.mu.Unlock()
	if !commit {
		b.lease.cancel(cause)
	}
}

func (b *backfillReadCloser) enqueue(p []byte) {
	b.mu.Lock()
	accepting := b.accepting
	b.mu.Unlock()
	if !accepting {
		return
	}
	if !b.lease.manager.tryReserveBuffer(len(p)) {
		b.stop(errBackfillAbandoned, false)
		return
	}
	chunk := append([]byte(nil), p...)

	b.mu.Lock()
	if !b.accepting {
		b.mu.Unlock()
		b.lease.manager.releaseBuffer(len(chunk))
		return
	}
	select {
	case b.chunks <- chunk:
		b.mu.Unlock()
	default:
		b.accepting = false
		close(b.chunks)
		b.mu.Unlock()
		b.lease.manager.releaseBuffer(len(chunk))
		b.lease.cancel(errBackfillAbandoned)
	}
}

func (b *backfillReadCloser) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)
	if n > 0 {
		b.enqueue(p[:n])
	}
	if errors.Is(err, io.EOF) {
		b.mu.Lock()
		b.eof = true
		b.mu.Unlock()
	} else if err != nil {
		b.stop(err, false)
	}
	return n, err //nolint:wrapcheck // must return unwrapped io.EOF per io.Reader contract
}

func (b *backfillReadCloser) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.src.Close()
		b.mu.Lock()
		complete := b.eof && b.closeErr == nil
		b.mu.Unlock()
		b.stop(errBackfillAbandoned, complete)
	})
	return errors.WithStack(b.closeErr)
}
