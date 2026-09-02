package cache

import (
	"context"
	"io"
	"net/http"
	"os"
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

const (
	errDiskStatTimeout     diskUnavailableError = "disk Stat timed out"
	errDiskOpenTimeout     diskUnavailableError = "disk Open timed out"
	errDiskBodyReadTimeout diskUnavailableError = "disk body Read timed out"
	errDiskCloseTimeout    diskUnavailableError = "disk reader Close timed out"
)

type diskUnavailableError string

func (e diskUnavailableError) Error() string { return string(e) + ": " + ErrTierUnavailable.Error() }

func (diskUnavailableError) Unwrap() error { return ErrTierUnavailable }

type diskReadBuffer struct {
	data [diskReadChunkSize]byte
}

type diskReadIsolation struct {
	ctx              context.Context
	readSlots        chan struct{}
	closeSlots       chan struct{}
	operationTimeout time.Duration
	readIdleTimeout  time.Duration
	degradedUntil    atomic.Int64
	buffers          sync.Pool
	metrics          diskMetricRecorder
}

func newDiskReadIsolation(
	ctx context.Context,
	concurrency int,
	operationTimeout time.Duration,
	readIdleTimeout time.Duration,
) *diskReadIsolation {
	isolation := &diskReadIsolation{
		ctx:              ctx,
		readSlots:        make(chan struct{}, concurrency),
		closeSlots:       make(chan struct{}, concurrency),
		operationTimeout: operationTimeout,
		readIdleTimeout:  readIdleTimeout,
		metrics:          defaultDiskMetrics,
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

// acquire waits within the caller's operation deadline while the breaker
// prevents new Stat and Open work from entering a degraded disk tier.
func (d *diskReadIsolation) acquire(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return errors.WithStack(cause)
	}
	if time.Now().UnixNano() < d.degradedUntil.Load() {
		return diskTierUnavailable("disk reads are temporarily degraded")
	}
	select {
	case d.readSlots <- struct{}{}:
		if time.Now().UnixNano() < d.degradedUntil.Load() {
			d.releaseRead()
			return diskTierUnavailable("disk reads are temporarily degraded")
		}
		return nil
	case <-ctx.Done():
		return errors.WithStack(context.Cause(ctx))
	case <-d.ctx.Done():
		return errors.WithStack(context.Cause(d.ctx))
	}
}

func (d *diskReadIsolation) acquireRead(ctx context.Context, timeout <-chan time.Time, timeoutErr error) error {
	if cause := context.Cause(ctx); cause != nil {
		return errors.WithStack(cause)
	}
	select {
	case d.readSlots <- struct{}{}:
		return nil
	case <-timeout:
		d.trip(context.WithoutCancel(ctx), diskReadOperationRead)
		return timeoutErr
	case <-ctx.Done():
		return errors.WithStack(context.Cause(ctx))
	case <-d.ctx.Done():
		return errors.WithStack(context.Cause(d.ctx))
	}
}

func (d *diskReadIsolation) releaseRead() {
	<-d.readSlots
}

func (d *diskReadIsolation) trip(ctx context.Context, operation diskReadOperation) {
	until := time.Now().Add(diskDegradedDuration).UnixNano()
	for {
		current := d.degradedUntil.Load()
		if current >= until {
			return
		}
		if d.degradedUntil.CompareAndSwap(current, until) {
			recordDiskReadEvent(ctx, d.metrics, diskReadEventBreakerTrip, operation, backendDisk)
			return
		}
	}
}

func diskTierUnavailable(message string) error {
	return errors.Wrap(ErrTierUnavailable, message)
}

func (d *diskReadIsolation) operationContext(
	ctx context.Context,
	timeoutErr error,
	operation diskReadOperation,
) (context.Context, func()) {
	parent, cancelParent := context.WithCancelCause(ctx)
	stopDiskCancel := context.AfterFunc(d.ctx, func() {
		cancelParent(context.Cause(d.ctx))
	})
	opCtx, cancelTimeout := context.WithTimeoutCause(parent, d.operationTimeout, timeoutErr)
	stopTrip := context.AfterFunc(opCtx, func() {
		if errors.Is(context.Cause(opCtx), timeoutErr) {
			d.trip(context.WithoutCancel(opCtx), operation)
		}
	})
	return opCtx, func() {
		stopTrip()
		cancelTimeout()
		stopDiskCancel()
		cancelParent(nil)
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
	opCtx, cleanup := d.operationContext(ctx, errDiskStatTimeout, diskReadOperationStat)
	if err := d.acquire(opCtx); err != nil {
		cleanup()
		return nil, err
	}
	result := make(chan diskStatResult)
	go func() {
		headers, err := stat(opCtx)
		d.releaseRead()
		defer cleanup()
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
	opCtx, cleanup := d.operationContext(ctx, errDiskOpenTimeout, diskReadOperationOpen)
	if err := d.acquire(opCtx); err != nil {
		cleanup()
		return nil, nil, err
	}
	result := make(chan diskOpenResult)
	go func() {
		reader, headers, err := open(opCtx)
		d.releaseRead()
		if reader == nil && err == nil {
			err = errors.New("disk Open returned a nil reader")
		}
		defer cleanup()
		select {
		case result <- diskOpenResult{reader: reader, headers: headers, err: err}:
		case <-opCtx.Done():
			if reader != nil {
				go func() { _ = reader.Close() }() //nolint:errcheck // The caller has already received the timeout or cancellation cause.
			}
		}
	}()
	select {
	case outcome := <-result:
		if outcome.err != nil {
			return nil, outcome.headers, errors.WithStack(outcome.err)
		}
		return newIsolatedDiskReader(ctx, outcome.reader, d), outcome.headers, nil
	case <-opCtx.Done():
		return nil, nil, errors.WithStack(context.Cause(opCtx))
	}
}

type diskReadResult struct {
	buffer *diskReadBuffer
	n      int
	err    error
}

type isolatedDiskReader struct {
	reader            io.ReadCloser
	isolation         *diskReadIsolation
	ctx               context.Context
	cancel            context.CancelCauseFunc
	readMu            sync.Mutex
	readTimer         *time.Timer
	readRequests      chan int
	readResult        chan diskReadResult
	readConsumed      chan struct{}
	readFinished      chan struct{}
	readWorkerDone    chan struct{}
	readWorkerStarted bool
	readStarted       atomic.Bool
	closeOnce         sync.Once
	done              chan struct{}
	closeErr          error
	closed            atomic.Bool
	stopDisk          chan func() bool
}

func newIsolatedDiskReader(
	ctx context.Context,
	reader io.ReadCloser,
	isolation *diskReadIsolation,
) *isolatedDiskReader {
	readerCtx, cancel := context.WithCancelCause(ctx)
	r := &isolatedDiskReader{
		reader:         reader,
		isolation:      isolation,
		ctx:            readerCtx,
		cancel:         cancel,
		readRequests:   make(chan int),
		readResult:     make(chan diskReadResult, 1),
		readConsumed:   make(chan struct{}, 1),
		readFinished:   make(chan struct{}, 1),
		readWorkerDone: make(chan struct{}),
		done:           make(chan struct{}),
		stopDisk:       make(chan func() bool, 1),
	}
	r.stopDisk <- context.AfterFunc(isolation.ctx, func() { r.startClose(context.Cause(isolation.ctx)) })
	context.AfterFunc(readerCtx, func() { r.startClose(context.Cause(readerCtx)) })
	return r
}

func (r *isolatedDiskReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.closed.Load() {
		return 0, os.ErrClosed
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	if cause := context.Cause(r.ctx); cause != nil {
		if errors.Is(cause, io.EOF) {
			return 0, io.EOF
		}
		return 0, errors.WithStack(cause)
	}
	r.readStarted.Store(true)
	if !r.readWorkerStarted {
		r.readWorkerStarted = true
		go r.runReadWorker()
	}
	r.startReadTimer()
	if err := r.isolation.acquireRead(r.ctx, r.readTimer.C, errDiskBodyReadTimeout); err != nil {
		r.stopReadTimer()
		r.startClose(err)
		return 0, err
	}

	readSize := min(len(p), diskReadChunkSize)
	r.readRequests <- readSize

	select {
	case outcome := <-r.readResult:
		r.stopReadTimer()
		if outcome.n < 0 || outcome.n > readSize {
			r.readConsumed <- struct{}{}
			<-r.readFinished
			err := errors.Errorf("invalid disk Read count %d", outcome.n)
			r.startClose(err)
			return 0, err
		}
		copy(p, outcome.buffer.data[:outcome.n])
		r.readConsumed <- struct{}{}
		<-r.readFinished
		if outcome.err != nil {
			r.startClose(outcome.err)
		}
		return outcome.n, outcome.err //nolint:wrapcheck // Preserve io.Reader errors, including io.EOF.
	case <-r.readTimer.C:
		r.isolation.trip(context.WithoutCancel(r.ctx), diskReadOperationRead)
		r.readConsumed <- struct{}{}
		r.startClose(errDiskBodyReadTimeout)
		return 0, errDiskBodyReadTimeout
	case <-r.ctx.Done():
		r.stopReadTimer()
		cause := context.Cause(r.ctx)
		r.readConsumed <- struct{}{}
		r.startClose(cause)
		return 0, errors.WithStack(cause)
	}
}

func (r *isolatedDiskReader) runReadWorker() {
	defer close(r.readWorkerDone)
	for readSize := range r.readRequests {
		buffer := r.isolation.getBuffer()
		n, err := r.reader.Read(buffer.data[:readSize])
		r.isolation.releaseRead()
		r.readResult <- diskReadResult{buffer: buffer, n: n, err: err}
		<-r.readConsumed
		r.isolation.putBuffer(buffer)
		r.readFinished <- struct{}{}
	}
}

func (r *isolatedDiskReader) stopReadWorker() {
	r.readMu.Lock()
	started := r.readWorkerStarted
	if started {
		close(r.readRequests)
	}
	r.readMu.Unlock()
	if started {
		<-r.readWorkerDone
	}
}

func (r *isolatedDiskReader) startReadTimer() {
	if r.readTimer == nil {
		r.readTimer = time.NewTimer(r.isolation.readIdleTimeout)
		return
	}
	r.readTimer.Reset(r.isolation.readIdleTimeout)
}

func (r *isolatedDiskReader) stopReadTimer() {
	if r.readTimer == nil || r.readTimer.Stop() {
		return
	}
	select {
	case <-r.readTimer.C:
	default:
	}
}

// RawFile exposes an untouched disk file to the git snapshot path so
// http.ServeContent can retain its sendfile fast path. Generic cache reads stay
// behind the per-Read isolation above.
func (r *isolatedDiskReader) RawFile() *os.File {
	if r.closed.Load() || r.readStarted.Load() {
		return nil
	}
	file, _ := r.reader.(*os.File)
	return file
}

func (r *isolatedDiskReader) startClose(cause error) {
	r.closeOnce.Do(func() {
		r.cancel(cause)
		go r.stopReadWorker()
		go func() {
			r.isolation.closeSlots <- struct{}{}
			r.closeErr = r.reader.Close()
			<-r.isolation.closeSlots
			(<-r.stopDisk)()
			close(r.done)
		}()
	})
}

func (r *isolatedDiskReader) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	r.startClose(context.Canceled)
	timer := time.NewTimer(r.isolation.operationTimeout)
	defer timer.Stop()
	select {
	case <-r.done:
		return errors.WithStack(r.closeErr)
	case <-timer.C:
		r.isolation.trip(context.WithoutCancel(r.ctx), diskReadOperationClose)
		return errDiskCloseTimeout
	}
}

var _ io.ReadCloser = (*isolatedDiskReader)(nil)
