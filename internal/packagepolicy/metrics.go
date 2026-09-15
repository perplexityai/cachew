package packagepolicy

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
)

type metricRecorder interface {
	record(context.Context, Decision, error, time.Duration)
	recordOutcome(context.Context, Decision, error)
	recordNotApplicable(context.Context)
}

func (m *clientMetrics) recordNotApplicable(ctx context.Context) {
	m.recordOutcome(ctx, Decision{Verdict: VerdictNotApplicable}, nil)
}

func (m *clientMetrics) recordOutcome(ctx context.Context, decision Decision, err error) {
	m.evaluations.Add(ctx, 1, m.attributes(decision, err))
}

type clientMetrics struct {
	provider    string
	evaluations metric.Int64Counter
	duration    metric.Float64Histogram
}

func newMetrics(provider string) *clientMetrics {
	meter := otel.Meter("cachew.package_policy")
	return &clientMetrics{
		provider: provider,
		evaluations: cachewmetrics.NewMetric[metric.Int64Counter](
			meter,
			"cachew.package_policy.evaluations_total",
			"{evaluations}",
			"Package policy evaluations by provider and outcome",
		),
		duration: cachewmetrics.NewHistogram(
			meter,
			"cachew.package_policy.evaluation_duration_seconds",
			"s",
			"Package policy evaluation duration by provider and outcome",
			cachewmetrics.LatencyBuckets(),
		),
	}
}

func (m *clientMetrics) record(ctx context.Context, decision Decision, err error, duration time.Duration) {
	attrs := m.attributes(decision, err)
	m.evaluations.Add(ctx, 1, attrs)
	m.duration.Record(ctx, duration.Seconds(), attrs)
}

func (m *clientMetrics) attributes(decision Decision, err error) metric.MeasurementOption {
	outcome := string(decision.Verdict)
	if err != nil || outcome == "" {
		outcome = "unavailable"
	}
	return metric.WithAttributes(
		attribute.String("provider", m.provider),
		attribute.String("outcome", outcome),
	)
}
