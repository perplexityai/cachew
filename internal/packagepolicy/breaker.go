package packagepolicy

import (
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

// Fixed thresholds; expose them in SocketConfig if a deployment ever needs tuning.
const (
	breakerFailureThreshold = 5
	breakerCooldown         = 30 * time.Second
)

var errProviderCircuitOpen = errors.New("socket policy: provider skipped after repeated failures")

// circuitBreaker skips the provider for breakerCooldown after breakerFailureThreshold
// consecutive failures so an outage fails open quickly instead of holding every request to its timeout.
type circuitBreaker struct {
	now func() time.Time

	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

func (b *circuitBreaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.now().Before(b.openUntil)
}

func (b *circuitBreaker) observe(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= breakerFailureThreshold {
		b.openUntil = b.now().Add(breakerCooldown)
		b.failures = 0
	}
}
