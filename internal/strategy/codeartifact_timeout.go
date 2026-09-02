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
	generation uint64
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
	r := &codeArtifactOriginBody{body: body, ctx: ctx, cancel: cancel, timeout: timeout}
	r.resetTimer()
	return r
}

func (r *codeArtifactOriginBody) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if n > 0 {
		r.resetTimer()
	}
	if errors.Is(context.Cause(r.ctx), errCodeArtifactOriginReadIdleTimeout) {
		return n, errCodeArtifactOriginReadIdleTimeout
	}
	return n, err //nolint:wrapcheck // Reader callers require an unwrapped io.EOF.
}

func (r *codeArtifactOriginBody) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.generation++
		if r.timer != nil {
			r.timer.Stop()
		}
		r.mu.Unlock()
		r.cancel(nil)
		r.closeErr = r.body.Close()
	})
	return errors.WithStack(r.closeErr)
}

func (r *codeArtifactOriginBody) resetTimer() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	// Replacing the timer is not enough because a callback may already be
	// runnable. The generation prevents stale callbacks from cancelling a body
	// after a later read made progress and armed a fresh idle window.
	r.generation++
	generation := r.generation
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(r.timeout, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed || generation != r.generation {
			return
		}
		r.cancel(errCodeArtifactOriginReadIdleTimeout)
	})
}

var _ io.ReadCloser = (*codeArtifactOriginBody)(nil)
