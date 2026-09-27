package httputil

import (
	"context"
	"time"
)

const cacheFillCancellationGrace = 30 * time.Second

// CacheFillContext lets a cache write finish after a client receives the complete
// response and disconnects. Callers must abort incomplete writes and cancel the
// returned context when finished; abandoned writes get at most 30 seconds.
func CacheFillContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stop := context.AfterFunc(parent, func() {
		timer := time.NewTimer(cacheFillCancellationGrace)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel()
		case <-ctx.Done():
		}
	})
	return ctx, func() {
		stop()
		cancel()
	}
}
