package packagepolicy //nolint:testpackage // White-box coverage is required for clock and metric injection.

import (
	"context"
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
	cache := newCachingEvaluator(inner, 10*time.Minute, metrics)
	now := time.Now()
	cache.now = func() time.Time { return now }

	for range 3 {
		decision, err := cache.Evaluate(t.Context(), testPURL)
		assert.NoError(t, err)
		assert.Equal(t, Decision{Verdict: VerdictDeny, Reasons: []string{"malware"}}, decision)
	}
	assert.Equal(t, 1, inner.calls)
	assert.Equal(t, int32(2), metrics.outcomes.Load())

	now = now.Add(10 * time.Minute)
	decision, err := cache.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
	assert.Equal(t, 2, inner.calls)
}

func TestCachingEvaluatorDoesNotCachePendingOrFailures(t *testing.T) {
	inner := &scriptedEvaluator{
		decisions: []Decision{{Verdict: VerdictPending}, {}, {Verdict: VerdictAllow}},
		errs:      []error{nil, errors.New("socket down"), nil},
	}
	cache := newCachingEvaluator(inner, time.Hour, &recordingMetrics{})

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

func TestFailClosedEvaluatorDeniesFailuresAndPending(t *testing.T) {
	providerErr := errors.New("socket down")
	inner := &scriptedEvaluator{
		decisions: []Decision{{}, {Verdict: VerdictPending, Reasons: []string{"notFound"}}, {Verdict: VerdictAllow}},
		errs:      []error{providerErr, nil, nil},
	}
	evaluator := failClosedEvaluator{Evaluator: inner}

	decision, err := evaluator.Evaluate(t.Context(), testPURL)
	assert.IsError(t, err, providerErr)
	assert.Equal(t, Decision{Verdict: VerdictDeny, Reasons: []string{"unavailable"}}, decision)
	decision, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, Decision{Verdict: VerdictDeny, Reasons: []string{"notFound"}}, decision)
	decision, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
}

func TestNewValidatesAndLayersPolicyOptions(t *testing.T) {
	socket := &SocketConfig{Organization: testOrganization, Token: testToken}
	_, err := New(Config{Socket: socket, OnFailure: "maybe"})
	assert.Error(t, err)
	_, err = New(Config{Socket: socket, VerdictTTL: -time.Second})
	assert.Error(t, err)

	evaluator, err := New(Config{Socket: socket, VerdictTTL: time.Minute, OnFailure: "deny", ExcludePURLs: []string{"pkg:npm/%40myorg/*"}})
	assert.NoError(t, err)
	excluding := evaluator.(*excludingEvaluator)
	failClosed := excluding.Evaluator.(failClosedEvaluator)
	caching := failClosed.Evaluator.(*cachingEvaluator)
	_ = caching.Evaluator.(*socketEvaluator)
}
