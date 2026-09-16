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

func TestMetricsEvaluatorKeepsAuditOnCanceledRequests(t *testing.T) {
	evaluator := &metricsEvaluator{
		Evaluator: staticEvaluator{decision: Decision{Verdict: VerdictAllow}},
		metrics:   &recordingMetrics{},
		audit:     true,
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	decision, err := evaluator.Evaluate(ctx, testPURL)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.True(t, decision.Audit)
}
