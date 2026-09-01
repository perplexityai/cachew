// Package admission provides non-blocking HTTP request load shedding.
package admission

import (
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/alecthomas/errors"
)

// Config controls process-wide HTTP request admission.
type Config struct {
	Limit    int `hcl:"limit,optional" help:"Maximum requests admitted through response completion (0 disables admission)." default:"0"`
	Reserved int `hcl:"reserved,optional" help:"Slots reserved for liveness, readiness, and authorized admin requests; must be smaller than limit." default:"0"`
}

// Limiter admits requests without queueing. Normal requests must fit both the
// normal and total ceilings, while protected routes consume only total capacity.
type Limiter struct {
	limit       int64
	normalLimit int64
	total       atomic.Int64
	normal      atomic.Int64
}

// New validates config and constructs a Limiter.
func New(config Config) (*Limiter, error) {
	switch {
	case config.Limit < 0:
		return nil, errors.New("request admission limit must not be negative")
	case config.Reserved < 0:
		return nil, errors.New("request admission reserved capacity must not be negative")
	case config.Limit == 0 && config.Reserved != 0:
		return nil, errors.New("request admission reserved capacity requires a positive limit")
	case config.Limit > 0 && config.Reserved >= config.Limit:
		return nil, errors.New("request admission reserved capacity must be smaller than the limit")
	}
	return &Limiter{
		limit:       int64(config.Limit),
		normalLimit: int64(config.Limit - config.Reserved),
	}, nil
}

// Middleware rejects saturated requests with a retryable 503 and otherwise
// holds admission until next returns.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	if l.limit == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected := isProtectedRequest(r)
		if !l.acquire(protected) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "server overloaded", http.StatusServiceUnavailable)
			return
		}
		defer l.release(protected)
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) acquire(protected bool) bool {
	if protected {
		return reserve(&l.total, l.limit)
	}
	if !reserve(&l.normal, l.normalLimit) {
		return false
	}
	if reserve(&l.total, l.limit) {
		return true
	}
	l.normal.Add(-1)
	return false
}

func (l *Limiter) release(protected bool) {
	l.total.Add(-1)
	if !protected {
		l.normal.Add(-1)
	}
}

func reserve(counter *atomic.Int64, limit int64) bool {
	for {
		current := counter.Load()
		if current >= limit {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func isProtectedRequest(r *http.Request) bool {
	// Absolute-form proxy requests target an upstream URL even when its path
	// happens to start with Cachew's reserved /admin prefix.
	if r.URL.IsAbs() {
		return false
	}
	path := r.URL.Path
	return path == "/_liveness" || path == "/_readiness" || path == "/admin" || strings.HasPrefix(path, "/admin/")
}
