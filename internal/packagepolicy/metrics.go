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

const (
	outcomeUnavailable = "unavailable"
	outcomeWouldDeny   = "would_deny"
)

type metricRecorder interface {
	recordDuration(context.Context, Decision, error, time.Duration)
	recordOutcome(context.Context, Decision, error)
	recordQueueWait(context.Context, time.Duration)
	recordInflight(context.Context, int64)
	recordCacheLookup(context.Context, bool)
	recordBreakerSkip(context.Context)
}

type metricsEvaluator struct {
	Evaluator
	metrics metricRecorder
	audit   bool
}

func (e *metricsEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	decision, err := e.Evaluator.Evaluate(ctx, purl)
	if cause := context.Cause(ctx); cause != nil {
		if decision.OriginalVerdict == "" && (err == nil || errors.Is(err, ErrOverloaded)) {
			decision.OriginalVerdict = decision.Verdict
		}
		decision.Verdict = VerdictDeny
		decision.Reasons = []string{"requestCanceled"}
		decision.Audit = e.audit
		return decision, errors.Wrap(cause, "package policy: request ended before evaluation completed")
	}
	decision.Audit = e.audit
	e.metrics.recordOutcome(context.WithoutCancel(ctx), decision, err)
	return decision, err //nolint:wrapcheck // Metrics must not add another provider error prefix.
}

func (m *clientMetrics) recordOutcome(ctx context.Context, decision Decision, err error) {
	if decision.Verdict == VerdictDeny && !errors.Is(err, ErrOverloaded) {
		err = nil
	}
	m.evaluations.Add(ctx, 1, m.attributes(decision, err))
}

type clientMetrics struct {
	provider      string
	evaluations   metric.Int64Counter
	providerCalls metric.Int64Counter
	duration      metric.Float64Histogram
	queueWait     metric.Float64Histogram
	inflight      metric.Int64UpDownCounter
	cacheLookups  metric.Int64Counter
	breakerSkips  metric.Int64Counter
}

func newMetrics() *clientMetrics {
	meter := otel.Meter("cachew.package_policy")
	inflight, err := meter.Int64UpDownCounter("cachew.package_policy.inflight",
		metric.WithUnit("{calls}"), metric.WithDescription("Active package policy provider calls"))
	if err != nil {
		panic(err)
	}
	return &clientMetrics{
		provider: "socket",
		inflight: inflight,
		evaluations: cachewmetrics.NewMetric[metric.Int64Counter](
			meter,
			"cachew.package_policy.evaluations_total",
			"{evaluations}",
			"Package requests by provider and final policy outcome",
		),
		providerCalls: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.package_policy.provider_calls_total", "{calls}", "Actual package policy provider calls by outcome",
		),
		queueWait: cachewmetrics.NewHistogram(
			meter, "cachew.package_policy.queue_wait_seconds", "s", "Wait for a package policy provider slot", cachewmetrics.LatencyBuckets(),
		),
		cacheLookups: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.package_policy.verdict_cache_total", "{lookups}", "Package policy verdict cache hits and misses",
		),
		breakerSkips: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.package_policy.breaker_skips_total", "{skips}", "Provider evaluations skipped by the circuit breaker",
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
	m.providerCalls.Add(ctx, 1, m.attributes(decision, err))
	m.duration.Record(ctx, duration.Seconds(), m.attributes(decision, err))
}

func (m *clientMetrics) recordQueueWait(ctx context.Context, duration time.Duration) {
	m.queueWait.Record(ctx, duration.Seconds(), metric.WithAttributes(attribute.String("provider", m.provider)))
}

func (m *clientMetrics) recordInflight(ctx context.Context, delta int64) {
	m.inflight.Add(ctx, delta, metric.WithAttributes(attribute.String("provider", m.provider)))
}

func (m *clientMetrics) recordCacheLookup(ctx context.Context, hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	m.cacheLookups.Add(ctx, 1, metric.WithAttributes(attribute.String("provider", m.provider), attribute.String("result", result)))
}

func (m *clientMetrics) recordBreakerSkip(ctx context.Context) {
	m.breakerSkips.Add(ctx, 1, metric.WithAttributes(attribute.String("provider", m.provider)))
}

func (m *clientMetrics) attributes(decision Decision, err error) metric.MeasurementOption {
	outcome := string(decision.Verdict)
	if err != nil || outcome == "" {
		outcome = outcomeUnavailable
	}
	if errors.Is(err, ErrOverloaded) {
		outcome = "overloaded"
	}
	if decision.Audit && decision.Verdict != VerdictNotApplicable {
		outcome = "would_allow"
		if decision.Verdict == VerdictDeny {
			outcome = outcomeWouldDeny
		}
	}
	return metric.WithAttributes(
		attribute.String("provider", m.provider),
		attribute.String("outcome", outcome),
	)
}
