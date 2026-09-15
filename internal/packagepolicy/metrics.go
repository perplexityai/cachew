package packagepolicy

import (
	"context"
	"time"

	"github.com/alecthomas/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
)

type metricRecorder interface {
	recordDuration(context.Context, Decision, error, time.Duration)
	recordOutcome(context.Context, Decision, error)
}

type metricsEvaluator struct {
	Evaluator
	metrics metricRecorder
}

func (e *metricsEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	decision, err := e.Evaluator.Evaluate(ctx, purl)
	if cause := context.Cause(ctx); cause != nil {
		return Decision{Verdict: VerdictDeny, Reasons: []string{"requestCanceled"}}, errors.Wrap(cause, "package policy: request ended before evaluation completed")
	}
	e.metrics.recordOutcome(context.WithoutCancel(ctx), decision, err)
	return decision, err //nolint:wrapcheck // Metrics must not add another provider error prefix.
}

func (m *clientMetrics) recordOutcome(ctx context.Context, decision Decision, err error) {
	if decision.Verdict == VerdictDeny {
		err = nil
	}
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
			"Package requests by provider and final policy outcome",
		),
		duration: cachewmetrics.NewHistogram(
			meter,
			"cachew.package_policy.evaluation_duration_seconds",
			"s",
			"Package policy API duration by provider and provider outcome",
			cachewmetrics.LatencyBuckets(),
		),
	}
}

func (m *clientMetrics) recordDuration(ctx context.Context, decision Decision, err error, duration time.Duration) {
	m.duration.Record(ctx, duration.Seconds(), m.attributes(decision, err))
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
