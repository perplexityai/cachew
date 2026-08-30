package strategy

import (
	"context"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/block/cachew/internal/cache"
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

type codeArtifactCacheTier string

const (
	codeArtifactCacheTierAll     codeArtifactCacheTier = "all"
	codeArtifactCacheTierNone    codeArtifactCacheTier = "none"
	codeArtifactCacheTierUnknown codeArtifactCacheTier = "unknown"
)

type codeArtifactRedirectEvent string

const (
	codeArtifactRedirectSameOrigin      codeArtifactRedirectEvent = "same_origin_rewritten"
	codeArtifactRedirectCrossOrigin     codeArtifactRedirectEvent = "cross_origin_followed"
	codeArtifactRedirectFailure         codeArtifactRedirectEvent = "cross_origin_failure"
	codeArtifactRedirectChainedRejected codeArtifactRedirectEvent = "chained_rejected"
)

type codeArtifactMetricRecorder interface {
	recordRequest(context.Context, codeArtifactCacheMode)
	recordCache(context.Context, codeArtifactCacheEvent, codeArtifactCacheTier)
	recordAuth(context.Context, codeArtifactAuthEvent)
	recordOrigin(context.Context, codeArtifactOriginObservation)
	recordRedirect(context.Context, codeArtifactRedirectEvent)
}

type codeArtifactOriginObservation struct {
	status   string
	format   string
	duration time.Duration
	size     int64
}

type codeArtifactMetrics struct {
	requests       metric.Int64Counter
	cache          metric.Int64Counter
	auth           metric.Int64Counter
	originRequests metric.Int64Counter
	originDuration metric.Float64Histogram
	originSize     metric.Float64Histogram
	redirects      metric.Int64Counter
}

func newCodeArtifactMetrics() *codeArtifactMetrics {
	meter := otel.Meter("cachew.codeartifact")
	return &codeArtifactMetrics{
		requests: cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.codeartifact.requests_total", "{requests}", "CodeArtifact requests by cache mode"),
		cache:    cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.codeartifact.cache_operations_total", "{operations}", "CodeArtifact cache operations by result"),
		auth:     cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.codeartifact.auth_events_total", "{events}", "CodeArtifact authorization token events"),
		originRequests: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.codeartifact.origin_requests_total", "{requests}", "CodeArtifact origin requests by status and package format",
		),
		originDuration: cachewmetrics.NewHistogram(
			meter, "cachew.codeartifact.origin_request_duration_seconds", "s", "CodeArtifact origin request duration through body close", cachewmetrics.LatencyBuckets(),
		),
		originSize: cachewmetrics.NewHistogram(
			meter, "cachew.codeartifact.origin_response_bytes", "By", "CodeArtifact origin response body size", cachewmetrics.ByteBuckets(),
		),
		redirects: cachewmetrics.NewMetric[metric.Int64Counter](
			meter, "cachew.codeartifact.redirects_total", "{redirects}", "CodeArtifact redirect outcomes",
		),
	}
}

func (m *codeArtifactMetrics) recordRequest(ctx context.Context, mode codeArtifactCacheMode) {
	m.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("cache_mode", string(mode))))
}

func (m *codeArtifactMetrics) recordCache(ctx context.Context, event codeArtifactCacheEvent, tier codeArtifactCacheTier) {
	m.cache.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event", string(event)),
		attribute.String("tier", string(tier)),
	))
}

func (m *codeArtifactMetrics) recordAuth(ctx context.Context, event codeArtifactAuthEvent) {
	m.auth.Add(ctx, 1, metric.WithAttributes(attribute.String("event", string(event))))
}

func (m *codeArtifactMetrics) recordOrigin(ctx context.Context, observation codeArtifactOriginObservation) {
	attrs := metric.WithAttributes(
		attribute.String("status", observation.status),
		attribute.String("format", observation.format),
	)
	m.originRequests.Add(ctx, 1, attrs)
	m.originDuration.Record(ctx, observation.duration.Seconds(), attrs)
	m.originSize.Record(ctx, float64(observation.size), attrs)
}

func (m *codeArtifactMetrics) recordRedirect(ctx context.Context, event codeArtifactRedirectEvent) {
	m.redirects.Add(ctx, 1, metric.WithAttributes(attribute.String("event", string(event))))
}

type observedCodeArtifactBody struct {
	io.ReadCloser
	ctx     context.Context
	metric  codeArtifactMetricRecorder
	status  int
	format  string
	started time.Time
	bytes   atomic.Int64
	once    sync.Once
}

func (b *observedCodeArtifactBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes.Add(int64(n))
	return n, err //nolint:wrapcheck // Reader callers require an unwrapped io.EOF.
}

func (b *observedCodeArtifactBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		b.metric.recordOrigin(
			context.WithoutCancel(b.ctx),
			codeArtifactOriginObservation{
				status:   strconv.Itoa(b.status),
				format:   b.format,
				duration: time.Since(b.started),
				size:     b.bytes.Load(),
			},
		)
	})
	return errors.WithStack(err)
}

func boundedCodeArtifactCacheTier(backend cache.BackendType) codeArtifactCacheTier {
	return codeArtifactCacheTier(backend)
}
