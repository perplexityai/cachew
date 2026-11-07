package strategy

import (
	"context"
	"net/http"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
	"github.com/block/cachew/internal/strategy/handler"
)

type ecrResult string

const (
	ecrResultHit         ecrResult = "hit"
	ecrResultMiss        ecrResult = "miss"
	ecrResultRedirect    ecrResult = "redirect"
	ecrResultMetadata    ecrResult = "metadata"
	ecrResultNotFound    ecrResult = "not_found"
	ecrResultRateLimited ecrResult = "rate_limited"
	ecrResultNotServed   ecrResult = "not_served"
	ecrResultFailure     ecrResult = "failure"
)

type ecrFailureReason string

const (
	ecrFailureDigestMismatch ecrFailureReason = "digest_mismatch"
	ecrFailureNoLength       ecrFailureReason = "no_length"
	ecrFailurePartial        ecrFailureReason = "partial"
	ecrFailureRejected       ecrFailureReason = "rejected"
	ecrFailureAuthorization  ecrFailureReason = "authorization"
	ecrFailureBadRedirect    ecrFailureReason = "bad_redirect"
	ecrFailureTransport      ecrFailureReason = "transport"
	ecrFailureUpstreamStatus ecrFailureReason = "upstream_status"
	ecrFailureCache          ecrFailureReason = "cache"
	ecrFailureInternal       ecrFailureReason = "internal"
)

const (
	ecrKindManifest = "manifest"
	ecrKindBlob     = "blob"
	// ecrKindUnknown labels requests refused before the path names a manifest
	// or blob.
	ecrKindUnknown = "unknown"
)

// ecrRequestOutcome is what one client request recorded. Every attribute is
// from a fixed set; repository names and digests are never labels.
type ecrRequestOutcome struct {
	kind   string // manifest, blob or unknown
	method string
	result ecrResult
	reason ecrFailureReason // set when result is failure
}

type ecrMetricRecorder interface {
	recordRequest(context.Context, ecrRequestOutcome)
	recordAuth(context.Context, originAuthEvent)
}

type ecrMetrics struct {
	requests metric.Int64Counter
	failures metric.Int64Counter
	auth     metric.Int64Counter
}

func newECRMetrics() *ecrMetrics {
	meter := otel.Meter("cachew.ecr")
	return &ecrMetrics{
		requests: cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.ecr.requests_total", "{requests}", "ECR requests by kind, method and result"),
		failures: cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.ecr.failures_total", "{failures}", "Failed ECR requests by kind and reason"),
		auth:     cachewmetrics.NewMetric[metric.Int64Counter](meter, "cachew.ecr.auth_events_total", "{events}", "ECR authorization token events"),
	}
}

func (m *ecrMetrics) recordRequest(ctx context.Context, outcome ecrRequestOutcome) {
	m.requests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("kind", outcome.kind),
		attribute.String("method", outcome.method),
		attribute.String("result", string(outcome.result)),
	))
	if outcome.result == ecrResultFailure {
		m.failures.Add(ctx, 1, metric.WithAttributes(
			attribute.String("kind", outcome.kind),
			attribute.String("reason", string(outcome.reason)),
		))
	}
}

func (m *ecrMetrics) recordAuth(ctx context.Context, event originAuthEvent) {
	m.auth.Add(ctx, 1, metric.WithAttributes(attribute.String("event", string(event))))
}

// ecrObservation collects one request's failure cause as it is found: in the
// serving goroutine, the transport, or the handler's fill goroutine that reads
// the digest-verified body. The first cause wins.
type ecrObservation struct {
	mu        sync.Mutex
	reason    ecrFailureReason
	notServed bool
}

type ecrObservationKey struct{}

func withECRObservation(ctx context.Context) (context.Context, *ecrObservation) {
	o := &ecrObservation{}
	return context.WithValue(ctx, ecrObservationKey{}, o), o
}

// ecrObservationFrom returns nil outside a served request; its methods accept
// a nil receiver.
func ecrObservationFrom(ctx context.Context) *ecrObservation {
	o, _ := ctx.Value(ecrObservationKey{}).(*ecrObservation)
	return o
}

func (o *ecrObservation) fail(reason ecrFailureReason) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.reason == "" {
		o.reason = reason
	}
}

func (o *ecrObservation) refuse() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.notServed = true
}

// outcome classifies a finished request from its status, its cache result
// header and any recorded cause. A manifest whose digest failed mid-stream
// still answered 200, so the recorded cause takes precedence over the status.
func (o *ecrObservation) outcome(kind, method string, status int, cacheResult string) ecrRequestOutcome {
	o.mu.Lock()
	reason, notServed := o.reason, o.notServed
	o.mu.Unlock()
	outcome := ecrRequestOutcome{kind: kind, method: method}
	if status == 0 {
		status = http.StatusOK
	}
	switch {
	case notServed:
		outcome.result = ecrResultNotServed
	case reason != "":
		outcome.result, outcome.reason = ecrResultFailure, reason
	case status == http.StatusTemporaryRedirect:
		outcome.result = ecrResultRedirect
	case status == http.StatusNotFound:
		outcome.result = ecrResultNotFound
	case status == http.StatusTooManyRequests:
		outcome.result = ecrResultRateLimited
	case cacheResult == handler.CacheResultHit && status < http.StatusInternalServerError:
		// Includes 304s and range answers served from the cache entry.
		outcome.result = ecrResultHit
	case status >= http.StatusBadRequest:
		outcome.result, outcome.reason = ecrResultFailure, ecrFailureUpstreamStatus
	case kind == ecrKindBlob:
		outcome.result = ecrResultMetadata
	default:
		outcome.result = ecrResultMiss
	}
	return outcome
}
