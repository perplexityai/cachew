package packagepolicy //nolint:testpackage // White-box coverage is required for metric recorder injection.

import (
	"context"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

type recordingMetrics struct {
	notApplicable int
}

func (r *recordingMetrics) record(context.Context, Decision, error, time.Duration) {}

func (r *recordingMetrics) recordNotApplicable(context.Context) {
	r.notApplicable++
}

func TestObserveNotApplicableRecordsProviderMetric(t *testing.T) {
	metrics := &recordingMetrics{}
	evaluator := &socketEvaluator{metrics: metrics}

	evaluator.ObserveNotApplicable(t.Context())

	assert.Equal(t, 1, metrics.notApplicable)
}
