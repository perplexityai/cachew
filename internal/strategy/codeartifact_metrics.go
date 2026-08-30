package strategy

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
)

type codeArtifactAuthEvent string

const (
	codeArtifactAuthReuse         codeArtifactAuthEvent = "reuse"
	codeArtifactAuthRefresh       codeArtifactAuthEvent = "refresh"
	codeArtifactAuthForcedRefresh codeArtifactAuthEvent = "forced_refresh"
	codeArtifactAuthFailure       codeArtifactAuthEvent = "failure"
)

type codeArtifactCacheEvent string

const (
	codeArtifactCacheHit          codeArtifactCacheEvent = "hit"
	codeArtifactCacheMiss         codeArtifactCacheEvent = "miss"
	codeArtifactCacheStored       codeArtifactCacheEvent = "stored"
	codeArtifactCacheReadFailure  codeArtifactCacheEvent = "read_failure"
	codeArtifactCacheWriteFailure codeArtifactCacheEvent = "write_failure"
	codeArtifactCacheNotCacheable codeArtifactCacheEvent = "not_cacheable"
)

type codeArtifactMetricRecorder interface {
	recordRequest(context.Context, codeArtifactCacheMode)
	recordCache(context.Context, codeArtifactCacheEvent)
	recordAuth(context.Context, codeArtifactAuthEvent)
}

type codeArtifactMetrics struct {
	requests metric.Int64Counter
	cache    metric.Int64Counter
	auth     metric.Int64Counter
}

func newCodeArtifactMetrics() *codeArtifactMetrics {
	meter := otel.Meter("cachew.codeartifact")
	return &codeArtifactMetrics{
		requests: cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.codeartifact.requests_total", "{requests}", "CodeArtifact requests by cache mode"),
		cache:    cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.codeartifact.cache_operations_total", "{operations}", "CodeArtifact cache operations by result"),
		auth:     cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.codeartifact.auth_events_total", "{events}", "CodeArtifact authorization token events"),
	}
}

func (m *codeArtifactMetrics) recordRequest(ctx context.Context, mode codeArtifactCacheMode) {
	m.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("cache_mode", string(mode))))
}

func (m *codeArtifactMetrics) recordCache(ctx context.Context, event codeArtifactCacheEvent) {
	m.cache.Add(ctx, 1, metric.WithAttributes(attribute.String("event", string(event))))
}

func (m *codeArtifactMetrics) recordAuth(ctx context.Context, event codeArtifactAuthEvent) {
	m.auth.Add(ctx, 1, metric.WithAttributes(attribute.String("event", string(event))))
}
