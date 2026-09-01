package packagepolicy //nolint:testpackage // White-box coverage is required for metric recorder injection.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

type recordingMetrics struct {
	evaluations   atomic.Int32
	notApplicable atomic.Int32
	recorded      chan struct{}
}

func (r *recordingMetrics) record(context.Context, Decision, error, time.Duration) {
	r.evaluations.Add(1)
	if r.recorded != nil {
		r.recorded <- struct{}{}
	}
}

func (r *recordingMetrics) recordNotApplicable(context.Context) {
	r.notApplicable.Add(1)
}

func TestObserveNotApplicableRecordsProviderMetric(t *testing.T) {
	metrics := &recordingMetrics{}
	evaluator := &socketEvaluator{metrics: metrics}

	evaluator.ObserveNotApplicable(t.Context())

	assert.Equal(t, int32(1), metrics.notApplicable.Load())
}
