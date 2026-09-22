package packagepolicy //nolint:testpackage // White-box coverage is required for clock and metric injection.

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

type scriptedEvaluator struct {
	decisions []Decision
	errs      []error
	calls     int
}

func (s *scriptedEvaluator) Evaluate(context.Context, string) (Decision, error) {
	i := min(s.calls, len(s.decisions)-1)
	s.calls++
	var err error
	if i < len(s.errs) {
		err = s.errs[i]
	}
	return s.decisions[i], err
}

func (*scriptedEvaluator) ObserveNotApplicable(context.Context) {}

func TestCachingEvaluatorReusesDefinitiveVerdictsUntilTTL(t *testing.T) {
	inner := &scriptedEvaluator{decisions: []Decision{
		{Verdict: VerdictDeny, Reasons: []string{"malware"}},
		{Verdict: VerdictAllow},
	}}
	metrics := &recordingMetrics{}
	cache := newCachingEvaluator(inner, 10*time.Minute, 15*time.Second, metrics)
	evaluator := &metricsEvaluator{Evaluator: cache, metrics: metrics}
	now := time.Now()
	cache.now = func() time.Time { return now }

	for i := range 3 {
		decision, err := evaluator.Evaluate(t.Context(), testPURL)
		assert.NoError(t, err)
		assert.Equal(t, Decision{Verdict: VerdictDeny, Reasons: []string{"malware"}, VerdictCacheHit: i > 0}, decision)
	}
	assert.Equal(t, 1, inner.calls)
	assert.Equal(t, int32(3), metrics.outcomes.Load())
	assert.Equal(t, int32(0), metrics.evaluations.Load())

	now = now.Add(10 * time.Minute)
	decision, err := evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
	assert.Equal(t, 2, inner.calls)
	assert.Equal(t, int32(4), metrics.outcomes.Load())
}

func TestCachingEvaluatorCanDisablePendingAndErrorCache(t *testing.T) {
	inner := &scriptedEvaluator{
		decisions: []Decision{{Verdict: VerdictPending}, {}, {Verdict: VerdictAllow}},
		errs:      []error{nil, errors.New("socket down"), nil},
	}
	cache := newCachingEvaluator(inner, time.Hour, 0, &recordingMetrics{})

	decision, err := cache.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictPending, decision.Verdict)
	_, err = cache.Evaluate(t.Context(), testPURL)
	assert.Error(t, err)
	decision, err = cache.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
	assert.Equal(t, 3, inner.calls)
}

func TestCachingEvaluatorBrieflyReusesPendingAndProviderErrors(t *testing.T) {
	for _, providerErr := range []error{nil, errors.New("socket down"), context.DeadlineExceeded} {
		inner := &scriptedEvaluator{
			decisions: []Decision{{Verdict: VerdictPending}, {Verdict: VerdictAllow}},
			errs:      []error{providerErr},
		}
		metrics := &recordingMetrics{}
		cache := newCachingEvaluator(inner, time.Minute, 15*time.Second, metrics)
		now := time.Now()
		cache.now = func() time.Time { return now }
		for i := range 3 {
			decision, err := cache.Evaluate(t.Context(), testPURL)
			assert.Equal(t, VerdictPending, decision.Verdict)
			assert.Equal(t, i > 0, decision.VerdictCacheHit)
			assert.IsError(t, err, providerErr)
			assert.False(t, Cacheable(decision, err))
		}
		assert.Equal(t, 1, inner.calls)
		assert.Equal(t, int32(2), metrics.cacheHits.Load())
		assert.Equal(t, int32(1), metrics.cacheMisses.Load())

		now = now.Add(15 * time.Second)
		decision, err := cache.Evaluate(t.Context(), testPURL)
		assert.NoError(t, err)
		assert.Equal(t, VerdictAllow, decision.Verdict)
		assert.Equal(t, 2, inner.calls)
	}
}

func TestCachingEvaluatorDoesNotReuseLocalFailures(t *testing.T) {
	for _, localErr := range []error{context.Canceled, ErrOverloaded, ErrCircuitOpen} {
		inner := &scriptedEvaluator{decisions: []Decision{{}}, errs: []error{localErr}}
		cache := newCachingEvaluator(inner, time.Minute, 15*time.Second, &recordingMetrics{})
		for range 2 {
			_, err := cache.Evaluate(t.Context(), testPURL)
			assert.IsError(t, err, localErr)
		}
		assert.Equal(t, 2, inner.calls)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("request abandoned")
	cancel(cause)
	inner := &scriptedEvaluator{decisions: []Decision{{}}, errs: []error{cause}}
	cache := newCachingEvaluator(inner, time.Minute, 15*time.Second, &recordingMetrics{})
	_, err := cache.Evaluate(ctx, testPURL)
	assert.IsError(t, err, cause)
	assert.Equal(t, 0, len(cache.verdicts))
}

func TestCachingEvaluatorCanDisableDefinitiveCache(t *testing.T) {
	inner := &scriptedEvaluator{decisions: []Decision{{Verdict: VerdictAllow}, {Verdict: VerdictDeny}}}
	cache := newCachingEvaluator(inner, 0, 15*time.Second, &recordingMetrics{})
	_, err := cache.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	decision, err := cache.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictDeny, decision.Verdict)
	assert.Equal(t, 2, inner.calls)
}

func TestFailClosedEvaluatorDeniesFailuresAndPending(t *testing.T) {
	providerErr := errors.New("socket down")
	inner := &scriptedEvaluator{
		decisions: []Decision{{}, {Verdict: VerdictPending, Reasons: []string{"notFound"}}, {Verdict: VerdictAllow}},
		errs:      []error{providerErr, nil, nil},
	}
	evaluator := failClosedEvaluator{Evaluator: inner}

	decision, err := evaluator.Evaluate(t.Context(), testPURL)
	assert.IsError(t, err, providerErr)
	assert.Equal(t, Decision{Verdict: VerdictDeny, Reasons: []string{outcomeUnavailable}}, decision)
	decision, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, Decision{Verdict: VerdictDeny, OriginalVerdict: VerdictPending, Reasons: []string{"notFound"}}, decision)
	decision, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
}

func TestNewValidatesAndLayersPolicyOptions(t *testing.T) {
	socket := &SocketConfig{APIURL: "https://api.socket.dev", Organization: testOrganization, Token: testToken}
	_, err := New(Config{Mode: "enforce", Socket: socket, OnFailure: "maybe"})
	assert.Error(t, err)
	_, err = New(Config{Mode: "enforce", Socket: socket, OnFailure: "allow", VerdictTTL: -time.Second})
	assert.Error(t, err)
	_, err = New(Config{Mode: "enforce", Socket: socket, OnFailure: "allow", PendingTTL: -time.Second})
	assert.Error(t, err)

	evaluator, err := New(Config{Mode: "enforce", Socket: socket, VerdictTTL: time.Minute, OnFailure: "deny", ExcludePURLs: []string{"pkg:npm/%40myorg/*"}})
	assert.NoError(t, err)
	excluding := evaluator.(*metricsEvaluator).Evaluator.(*excludingEvaluator)
	failClosed := excluding.Evaluator.(failClosedEvaluator)
	caching := failClosed.Evaluator.(*cachingEvaluator)
	_ = caching.Evaluator.(*socketEvaluator)
}

func TestCachingEvaluatorEvictsLeastRecentlyUsedAtCapacity(t *testing.T) {
	inner := &scriptedEvaluator{decisions: []Decision{{Verdict: VerdictAllow}}}
	cache := newCachingEvaluator(inner, time.Minute, 0, &recordingMetrics{})
	now := time.Now()
	cache.now = func() time.Time { return now }
	for i := range maxCachedVerdicts {
		_, err := cache.Evaluate(t.Context(), testPURL+strconv.Itoa(i))
		assert.NoError(t, err)
	}
	_, err := cache.Evaluate(t.Context(), testPURL+"0")
	assert.NoError(t, err)
	_, err = cache.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	_, err = cache.Evaluate(t.Context(), testPURL+"0")
	assert.NoError(t, err)
	assert.Equal(t, maxCachedVerdicts+1, inner.calls)
	_, err = cache.Evaluate(t.Context(), testPURL+"1")
	assert.NoError(t, err)
	assert.Equal(t, maxCachedVerdicts+2, inner.calls)
	assert.Equal(t, maxCachedVerdicts, len(cache.verdicts))

	now = now.Add(time.Minute)
	_, err = cache.Evaluate(t.Context(), testPURL+"0")
	assert.NoError(t, err)
	assert.Equal(t, maxCachedVerdicts+3, inner.calls)
	assert.Equal(t, maxCachedVerdicts, len(cache.verdicts))
}
