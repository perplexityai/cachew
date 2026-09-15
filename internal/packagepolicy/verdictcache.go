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
	expiresAt time.Time
	position  *list.Element
}

// cachingEvaluator reuses definitive verdicts so cache hits and repeated downloads do not
// each cost a provider call, while a changed provider verdict still takes effect within ttl.
type cachingEvaluator struct {
	Evaluator
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	verdicts map[string]cachedVerdict
	recent   list.List
}

func newCachingEvaluator(inner Evaluator, ttl time.Duration) *cachingEvaluator {
	return &cachingEvaluator{
		Evaluator: inner,
		ttl:       ttl,
		now:       time.Now,
		verdicts:  make(map[string]cachedVerdict),
	}
}

func (c *cachingEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	if decision, ok := c.lookup(purl); ok {
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
		c.recent.Remove(entry.position)
		delete(c.verdicts, purl)
		return Decision{}, false
	}
	c.recent.MoveToFront(entry.position)
	return entry.decision, true
}

func (c *cachingEvaluator) store(purl string, decision Decision) {
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
	entry.expiresAt = c.now().Add(c.ttl)
	c.verdicts[purl] = entry
}
