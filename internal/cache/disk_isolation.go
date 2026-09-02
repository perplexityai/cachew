package cache

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/errors"
)

const (
	defaultDiskReadConcurrency  = 64
	maxDiskReadConcurrency      = 4096
	defaultDiskOperationTimeout = 2 * time.Second
	defaultDiskReadIdleTimeout  = 30 * time.Second
	diskReadChunkSize           = 256 * 1024
	diskDegradedDuration        = 30 * time.Second
)

type diskReadBuffer struct {
	data [diskReadChunkSize]byte
}

type diskReadIsolation struct {
	ctx              context.Context
	slots            chan struct{}
	operationTimeout time.Duration
	readIdleTimeout  time.Duration
	degradedUntil    atomic.Int64
	buffers          sync.Pool
}

func newDiskReadIsolation(
	ctx context.Context,
	concurrency int,
	operationTimeout time.Duration,
	readIdleTimeout time.Duration,
) *diskReadIsolation {
	isolation := &diskReadIsolation{
		ctx:              ctx,
		slots:            make(chan struct{}, concurrency),
		operationTimeout: operationTimeout,
		readIdleTimeout:  readIdleTimeout,
	}
	isolation.buffers.New = func() any { return &diskReadBuffer{} }
	return isolation
}

func (d *diskReadIsolation) getBuffer() *diskReadBuffer {
	return d.buffers.Get().(*diskReadBuffer)
}

func (d *diskReadIsolation) putBuffer(buffer *diskReadBuffer) {
	if buffer != nil {
		d.buffers.Put(buffer)
	}
}

func (d *diskReadIsolation) acquire(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return errors.WithStack(cause)
	}
	if cause := context.Cause(d.ctx); cause != nil {
		return errors.WithStack(cause)
	}
	if time.Now().UnixNano() < d.degradedUntil.Load() {
		return diskTierUnavailable("disk reads are temporarily degraded")
	}
	select {
	case d.slots <- struct{}{}:
		return nil
	default:
		return diskTierUnavailable("disk read concurrency is exhausted")
	}
}

func (d *diskReadIsolation) release() {
	<-d.slots
}

func (d *diskReadIsolation) trip() {
	until := time.Now().Add(diskDegradedDuration).UnixNano()
	for {
		current := d.degradedUntil.Load()
		if current >= until || d.degradedUntil.CompareAndSwap(current, until) {
			return
		}
	}
}

func diskTierUnavailable(message string) error {
	return errors.Wrap(ErrTierUnavailable, message)
}

func (d *diskReadIsolation) operationContext(ctx context.Context) (context.Context, context.CancelCauseFunc, func()) {
	opCtx, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(d.ctx, func() {
		cancel(context.Cause(d.ctx))
	})
	return opCtx, cancel, func() {
		stop()
		cancel(nil)
	}
}

type diskStatResult struct {
	headers http.Header
	err     error
}

func (d *diskReadIsolation) stat(
	ctx context.Context,
	stat func(context.Context) (http.Header, error),
) (http.Header, error) {
	if err := d.acquire(ctx); err != nil {
		return nil, err
	}
	opCtx, cancel, cleanup := d.operationContext(ctx)
	result := make(chan diskStatResult)
	go func() {
		defer d.release()
		defer cleanup()
		timeoutErr := diskTierUnavailable("disk Stat timed out")
		timer := time.AfterFunc(d.operationTimeout, func() {
			d.trip()
			cancel(timeoutErr)
		})
		headers, err := stat(opCtx)
		if !timer.Stop() {
			cancel(timeoutErr)
			return
		}
		if context.Cause(opCtx) != nil {
			return
		}
		select {
		case result <- diskStatResult{headers: headers, err: err}:
		case <-opCtx.Done():
		}
	}()
	select {
	case outcome := <-result:
		return outcome.headers, errors.WithStack(outcome.err)
	case <-opCtx.Done():
		return nil, errors.WithStack(context.Cause(opCtx))
	}
}

type diskOpenResult struct {
	reader  io.ReadCloser
	headers http.Header
	err     error
}

func (d *diskReadIsolation) open(
	ctx context.Context,
	open func(context.Context) (io.ReadCloser, http.Header, error),
) (io.ReadCloser, http.Header, error) {
	if err := d.acquire(ctx); err != nil {
		return nil, nil, err
	}
	opCtx, cancel, cleanup := d.operationContext(ctx)
	result := make(chan diskOpenResult)
	go func() {
		timeoutErr := diskTierUnavailable("disk Open timed out")
		timer := time.AfterFunc(d.operationTimeout, func() {
			d.trip()
			cancel(timeoutErr)
		})
		reader, headers, err := open(opCtx)
		if reader == nil && err == nil {
			err = errors.New("disk Open returned a nil reader")
		}
		if !timer.Stop() {
			cancel(timeoutErr)
			if reader != nil {
				_ = reader.Close() //nolint:errcheck // The timeout is already the caller-visible error.
			}
			d.release()
			cleanup()
			return
		}
		outcome := diskOpenResult{reader: reader, headers: headers, err: err}
		select {
		case result <- outcome:
			if err != nil {
				d.release()
				cleanup()
			}
		case <-opCtx.Done():
			if reader != nil {
				_ = reader.Close() //nolint:errcheck // The caller has already received the timeout or cancellation cause.
			}
			d.release()
			cleanup()
		}
	}()
	select {
	case outcome := <-result:
		if outcome.err != nil {
			return nil, outcome.headers, errors.WithStack(outcome.err)
		}
		reader := newIsolatedDiskReader(opCtx, outcome.reader, cancel, cleanup, d)
		if cause := context.Cause(opCtx); cause != nil {
			return nil, nil, errors.WithStack(cause)
		}
		return reader, outcome.headers, nil
	case <-opCtx.Done():
		return nil, nil, errors.WithStack(context.Cause(opCtx))
	}
}

type diskReaderCloser struct {
	reader    io.ReadCloser
	timeout   time.Duration
	onTimeout func()
	once      sync.Once
	done      chan struct{}
	err       error
}

func newDiskReaderCloser(reader io.ReadCloser, timeout time.Duration, onTimeout func()) *diskReaderCloser {
	return &diskReaderCloser{reader: reader, timeout: timeout, onTimeout: onTimeout, done: make(chan struct{})}
}

func (c *diskReaderCloser) close() {
	c.once.Do(func() {
		timer := time.AfterFunc(c.timeout, c.onTimeout)
		c.err = c.reader.Close()
		timer.Stop()
		close(c.done)
	})
}

type isolatedDiskReader struct {
	ctx        context.Context
	cancel     context.CancelCauseFunc
	cleanup    func()
	isolation  *diskReadIsolation
	closer     *diskReaderCloser
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	done       chan struct{}
	stopCancel func() bool
	closeErr   error
	closed     atomic.Bool
}

func newIsolatedDiskReader(
	ctx context.Context,
	reader io.ReadCloser,
	cancel context.CancelCauseFunc,
	cleanup func(),
	isolation *diskReadIsolation,
) *isolatedDiskReader {
	pipeReader, pipeWriter := io.Pipe()
	r := &isolatedDiskReader{
		ctx:        ctx,
		cancel:     cancel,
		cleanup:    cleanup,
		isolation:  isolation,
		pipeReader: pipeReader,
		pipeWriter: pipeWriter,
		done:       make(chan struct{}),
	}
	r.closer = newDiskReaderCloser(reader, isolation.operationTimeout, func() {
		isolation.trip()
		cancel(diskTierUnavailable("disk reader Close timed out"))
	})
	r.stopCancel = context.AfterFunc(ctx, func() {
		cause := context.Cause(ctx)
		_ = r.pipeWriter.CloseWithError(cause) //nolint:errcheck // The worker observes the same cancellation cause.
		r.closer.close()
	})
	go r.run(reader)
	return r
}

func (r *isolatedDiskReader) run(reader io.Reader) {
	var terminal error
	defer func() {
		_ = r.pipeWriter.CloseWithError(terminal) //nolint:errcheck // The reader owns the caller-visible stream error.
		r.closer.close()
		<-r.closer.done
		r.closeErr = r.closer.err
		r.stopCancel()
		r.isolation.release()
		r.cleanup()
		close(r.done)
	}()
	// The worker owns the buffer because a kernel Read may complete after its
	// timeout; piping the result prevents that late completion from mutating
	// caller memory. The lifecycle slot remains held until Close also finishes.
	buffer := r.isolation.getBuffer()
	defer r.isolation.putBuffer(buffer)
	timeoutErr := diskTierUnavailable("disk body Read timed out")
	timer := time.AfterFunc(r.isolation.readIdleTimeout, func() {
		r.isolation.trip()
		r.cancel(timeoutErr)
	})
	defer timer.Stop()
	for {
		n, err := reader.Read(buffer.data[:])
		if !timer.Stop() {
			r.cancel(timeoutErr)
			terminal = timeoutErr
			return
		}
		if cause := context.Cause(r.ctx); cause != nil {
			terminal = cause
			return
		}
		if n > 0 {
			if _, writeErr := r.pipeWriter.Write(buffer.data[:n]); writeErr != nil {
				if cause := context.Cause(r.ctx); cause != nil {
					terminal = cause
				} else {
					terminal = writeErr
				}
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				terminal = err
			}
			return
		}
		timer.Reset(r.isolation.readIdleTimeout)
	}
}

func (r *isolatedDiskReader) Read(p []byte) (int, error) {
	if r.closed.Load() {
		return 0, errors.New("disk reader closed")
	}
	n, err := r.pipeReader.Read(p)
	return n, err //nolint:wrapcheck // Preserve io.Reader errors, including io.EOF and the timeout sentinel.
}

func (r *isolatedDiskReader) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	r.cancel(context.Canceled)
	timer := time.NewTimer(r.isolation.operationTimeout)
	defer timer.Stop()
	select {
	case <-r.done:
		return errors.WithStack(r.closeErr)
	case <-timer.C:
		r.isolation.trip()
		return diskTierUnavailable("disk reader Close timed out")
	}
}

var _ io.ReadCloser = (*isolatedDiskReader)(nil)
