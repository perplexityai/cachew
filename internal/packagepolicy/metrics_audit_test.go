package packagepolicy //nolint:testpackage // White-box coverage of the metrics decorator.

import (
	"context"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

type staticEvaluator struct {
	decision Decision
	err      error
}

func (s staticEvaluator) Evaluate(context.Context, string) (Decision, error) {
	return s.decision, s.err
}

func (staticEvaluator) ObserveNotApplicable(context.Context) {}

func TestMetricsEvaluatorPreservesResultOnCanceledRequests(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		err      error
		original Verdict
	}{
		{"cached allow", Decision{Verdict: VerdictAllow, VerdictCacheHit: true}, nil, VerdictAllow},
		{"exclusion", Decision{Verdict: VerdictNotApplicable}, nil, VerdictNotApplicable},
		{"pending fail closed", Decision{Verdict: VerdictDeny, OriginalVerdict: VerdictPending}, nil, VerdictPending},
		{"overload", Decision{Verdict: VerdictDeny}, ErrOverloaded, VerdictDeny},
		{"original allow", Decision{Verdict: VerdictDeny, OriginalVerdict: VerdictAllow}, context.Canceled, VerdictAllow},
		{"no result", Decision{Verdict: VerdictDeny}, context.Canceled, ""},
		{"provider failure", Decision{Verdict: VerdictDeny}, errors.New("provider failed"), ""},
	}
	for _, mode := range []string{ModeEnforce, ModeAudit} {
		for _, test := range tests {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				metrics := &recordingMetrics{}
				evaluator := &metricsEvaluator{
					Evaluator: staticEvaluator{decision: test.decision, err: test.err},
					metrics:   metrics,
					audit:     mode == ModeAudit,
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				decision, err := evaluator.Evaluate(ctx, testPURL)
				assert.IsError(t, err, context.Canceled)
				assert.Equal(t, Decision{
					Verdict: VerdictDeny, OriginalVerdict: test.original, Reasons: []string{"requestCanceled"},
					VerdictCacheHit: test.decision.VerdictCacheHit, Audit: mode == ModeAudit,
				}, decision)
				assert.Equal(t, int32(0), metrics.outcomes.Load())
			})
		}
	}
}
