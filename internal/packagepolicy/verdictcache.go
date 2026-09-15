package packagepolicy

import (
	"context"
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

// ponytail: flat cap with arbitrary eviction; switch to an LRU if unique PURL churn ever approaches it.
const maxCachedVerdicts = 100_000

type cachedVerdict struct {
	decision  Decision
	expiresAt time.Time
}

// cachingEvaluator reuses definitive verdicts so cache hits and repeated downloads do not
// each cost a provider call, while a changed provider verdict still takes effect within ttl.
type cachingEvaluator struct {
	Evaluator
	ttl     time.Duration
	now     func() time.Time
	metrics metricRecorder

	mu       sync.Mutex
	verdicts map[string]cachedVerdict
}

func newCachingEvaluator(inner Evaluator, ttl time.Duration, metrics metricRecorder) *cachingEvaluator {
	return &cachingEvaluator{
		Evaluator: inner,
		ttl:       ttl,
		now:       time.Now,
		metrics:   metrics,
		verdicts:  make(map[string]cachedVerdict),
	}
}

// Evaluate serves allow and deny verdicts from the cache; pending results and provider failures are never cached.
func (c *cachingEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	if decision, ok := c.lookup(purl); ok {
		c.metrics.recordOutcome(ctx, decision, nil)
		return decision, nil
	}
	decision, err := c.Evaluator.Evaluate(ctx, purl)
	if err != nil {
		return decision, errors.Wrap(err, "package policy: evaluate provider")
	}
	if decision.Verdict == VerdictAllow || decision.Verdict == VerdictDeny {
		c.store(purl, decision)
	}
	return decision, nil
}

func (c *cachingEvaluator) lookup(purl string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.verdicts[purl]
	if !ok {
		return Decision{}, false
	}
	if !c.now().Before(entry.expiresAt) {
		delete(c.verdicts, purl)
		return Decision{}, false
	}
	return entry.decision, true
}

func (c *cachingEvaluator) store(purl string, decision Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.verdicts) >= maxCachedVerdicts {
		for key, entry := range c.verdicts {
			if !now.Before(entry.expiresAt) {
				delete(c.verdicts, key)
			}
		}
	}
	for key := range c.verdicts {
		if len(c.verdicts) < maxCachedVerdicts {
			break
		}
		delete(c.verdicts, key)
	}
	c.verdicts[purl] = cachedVerdict{decision: decision, expiresAt: now.Add(c.ttl)}
}
