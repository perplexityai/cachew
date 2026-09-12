package strategy

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
)

type githubObjectsMetrics struct {
	cacheLookups   metric.Int64Counter
	originRequests metric.Int64Counter
	originDuration metric.Float64Histogram
	requestPaths   metric.Float64Histogram
}

func newGitHubObjectsMetrics() *githubObjectsMetrics {
	meter := otel.Meter("cachew.github_objects")
	return &githubObjectsMetrics{
		cacheLookups: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.github_objects.cache_lookups_total", "{lookups}", "Immutable GitHub object cache lookups",
		),
		originRequests: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.github_objects.origin_requests_total", "{requests}", "GitHub GraphQL requests by result",
		),
		originDuration: cachewmetrics.NewHistogram(
			meter, "cachew.github_objects.origin_request_duration_seconds", "s", "GitHub GraphQL request duration", cachewmetrics.FastLatencyBuckets(),
		),
		requestPaths: cachewmetrics.NewHistogram(
			meter, "cachew.github_objects.request_paths", "{paths}", "Immutable GitHub object paths per request", cachewmetrics.SmallCountBuckets(),
		),
	}
}

func (m *githubObjectsMetrics) recordCacheLookup(ctx context.Context, found bool) {
	result := "miss"
	if found {
		result = "hit"
	}
	m.cacheLookups.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

func (m *githubObjectsMetrics) recordOrigin(ctx context.Context, result string, startedAt time.Time) {
	attributes := metric.WithAttributes(attribute.String("result", result))
	m.originRequests.Add(ctx, 1, attributes)
	m.originDuration.Record(ctx, time.Since(startedAt).Seconds(), attributes)
}

func (m *githubObjectsMetrics) recordRequest(ctx context.Context, paths int) {
	m.requestPaths.Record(ctx, float64(paths))
}
