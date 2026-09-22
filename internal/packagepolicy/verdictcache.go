package packagepolicy

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

const maxCachedVerdicts = 100_000

type cachedVerdict struct {
	decision  Decision
	err       error
	expiresAt time.Time
	position  *list.Element
}

// cachingEvaluator bounds approval age while briefly reusing inconclusive results to avoid
// repeated provider calls for every artifact belonging to the same package version.
type cachingEvaluator struct {
	Evaluator
	ttl        time.Duration
	pendingTTL time.Duration
	metrics    metricRecorder
	now        func() time.Time

	mu       sync.Mutex
	verdicts map[string]cachedVerdict
	recent   list.List
}

func newCachingEvaluator(inner Evaluator, ttl, pendingTTL time.Duration, metrics metricRecorder) *cachingEvaluator {
	return &cachingEvaluator{
		Evaluator:  inner,
		ttl:        ttl,
		pendingTTL: pendingTTL,
		metrics:    metrics,
		now:        time.Now,
		verdicts:   make(map[string]cachedVerdict),
	}
}

func (c *cachingEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	entry, hit := c.lookup(purl)
	if ctx.Err() == nil {
		c.metrics.recordCacheLookup(context.WithoutCancel(ctx), hit)
	}
	if hit {
		entry.decision.VerdictCacheHit = true
		return entry.decision, entry.err
	}
	decision, err := c.Evaluator.Evaluate(ctx, purl)
	if err != nil {
		err = errors.Wrap(err, "package policy: evaluate provider")
	}
	ttl := c.ttl
	if err != nil || decision.Verdict == VerdictPending {
		ttl = c.pendingTTL
	} else if decision.Verdict != VerdictAllow && decision.Verdict != VerdictDeny {
		return decision, nil
	}
	if ttl > 0 && ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrOverloaded) && !errors.Is(err, ErrCircuitOpen) {
		c.store(purl, decision, err, ttl)
	}
	return decision, err
}

func (c *cachingEvaluator) lookup(purl string) (cachedVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.verdicts[purl]
	if !ok {
		return cachedVerdict{}, false
	}
	if !c.now().Before(entry.expiresAt) {
		c.recent.Remove(entry.position)
		delete(c.verdicts, purl)
		return cachedVerdict{}, false
	}
	c.recent.MoveToFront(entry.position)
	return entry, true
}

func (c *cachingEvaluator) store(purl string, decision Decision, err error, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.verdicts[purl]
	if ok {
		c.recent.MoveToFront(entry.position)
	} else {
		if len(c.verdicts) >= maxCachedVerdicts {
			oldest := c.recent.Back()
			delete(c.verdicts, oldest.Value.(string))
			c.recent.Remove(oldest)
		}
		entry.position = c.recent.PushFront(purl)
	}
	entry.decision = decision
	entry.err = err
	entry.expiresAt = c.now().Add(ttl)
	c.verdicts[purl] = entry
}
