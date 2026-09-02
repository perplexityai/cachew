package strategy

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

var errCodeArtifactOriginReadIdleTimeout = errors.New("CodeArtifact origin body read idle timeout")

type codeArtifactOriginBody struct {
	body    io.ReadCloser
	ctx     context.Context
	cancel  context.CancelCauseFunc
	timeout time.Duration

	mu         sync.Mutex
	timer      *time.Timer
	timerWG    sync.WaitGroup
	timerArmed bool
	reading    bool
	closed     bool
	closeOnce  sync.Once
	closeErr   error
}

func newCodeArtifactOriginBody(
	ctx context.Context,
	body io.ReadCloser,
	cancel context.CancelCauseFunc,
	timeout time.Duration,
) io.ReadCloser {
	if timeout <= 0 {
		timeout = defaultCodeArtifactOriginReadIdleTimeout
	}
	return &codeArtifactOriginBody{body: body, ctx: ctx, cancel: cancel, timeout: timeout}
}

func (r *codeArtifactOriginBody) Read(p []byte) (int, error) {
	r.startRead()
	n, err := r.body.Read(p)
	r.finishRead()
	if errors.Is(context.Cause(r.ctx), errCodeArtifactOriginReadIdleTimeout) {
		return n, errCodeArtifactOriginReadIdleTimeout
	}
	return n, err //nolint:wrapcheck // Reader callers require an unwrapped io.EOF.
}

func (r *codeArtifactOriginBody) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.stopReadTimer()
		r.cancel(nil)
		r.closeErr = r.body.Close()
	})
	return errors.WithStack(r.closeErr)
}

func (r *codeArtifactOriginBody) startRead() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.reading = true
	r.timerArmed = true
	r.timerWG.Add(1)
	if r.timer == nil {
		r.timer = time.AfterFunc(r.timeout, r.timeoutRead)
		return
	}
	r.timer.Reset(r.timeout)
}

func (r *codeArtifactOriginBody) finishRead() {
	r.stopReadTimer()
}

func (r *codeArtifactOriginBody) stopReadTimer() {
	r.mu.Lock()
	r.reading = false
	if !r.timerArmed {
		r.mu.Unlock()
		return
	}
	r.timerArmed = false
	stopped := r.timer.Stop()
	r.mu.Unlock()
	// A false Stop means the callback may still be waiting for r.mu. Waiting
	// here prevents that callback from leaking into a later Reset cycle.
	if stopped {
		r.timerWG.Done()
	}
	r.timerWG.Wait()
}

func (r *codeArtifactOriginBody) timeoutRead() {
	defer r.timerWG.Done()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.reading {
		return
	}
	r.cancel(errCodeArtifactOriginReadIdleTimeout)
}

var _ io.ReadCloser = (*codeArtifactOriginBody)(nil)
