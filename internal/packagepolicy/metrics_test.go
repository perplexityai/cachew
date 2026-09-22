package packagepolicy //nolint:testpackage // White-box coverage is required for metric recorder injection.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type recordingMetrics struct {
	evaluations   atomic.Int32
	outcomes      atomic.Int32
	notApplicable atomic.Int32
	cacheHits     atomic.Int32
	cacheMisses   atomic.Int32
	recorded      chan struct{}
}

func (r *recordingMetrics) recordOutcome(_ context.Context, decision Decision, _ error) {
	r.outcomes.Add(1)
	if decision.Verdict == VerdictNotApplicable {
		r.notApplicable.Add(1)
	}
}

func (r *recordingMetrics) recordDuration(context.Context, Decision, error, time.Duration) {
	r.evaluations.Add(1)
	if r.recorded != nil {
		r.recorded <- struct{}{}
	}
}

func (*recordingMetrics) recordQueueWait(context.Context, time.Duration) {}

func (*recordingMetrics) recordInflight(context.Context, int64) {}

func (r *recordingMetrics) recordCacheLookup(_ context.Context, hit bool) {
	if hit {
		r.cacheHits.Add(1)
	} else {
		r.cacheMisses.Add(1)
	}
}

func (*recordingMetrics) recordBreakerSkip(context.Context) {}

func TestObserveNotApplicableRecordsProviderMetric(t *testing.T) {
	metrics := &recordingMetrics{}
	evaluator := &metricsEvaluator{Evaluator: &socketEvaluator{metrics: metrics}}

	evaluator.ObserveNotApplicable(t.Context())

	assert.Equal(t, int32(1), metrics.notApplicable.Load())
	assert.Equal(t, int32(1), metrics.outcomes.Load())
	assert.Equal(t, int32(0), metrics.evaluations.Load())
}

func TestNewRecordsFinalOutcomeAndProviderLatency(t *testing.T) {
	tests := []struct {
		outcome  string
		response string
		status   int
	}{
		{outcome: "allow", response: testAllowResponse, status: http.StatusOK},
		{outcome: "deny", response: testDenyResponse, status: http.StatusOK},
		{outcome: "pending", response: `{"alerts":[{"type":"pendingScan"}]}`, status: http.StatusOK},
		{outcome: "unavailable", status: http.StatusServiceUnavailable},
	}
	for _, mode := range []struct {
		policy    string
		onFailure string
	}{
		{policy: ModeEnforce, onFailure: "allow"},
		{policy: ModeEnforce, onFailure: "deny"},
		{policy: ModeAudit, onFailure: "allow"},
		{policy: ModeAudit, onFailure: "deny"},
	} {
		for _, test := range tests {
			t.Run(mode.policy+"/"+mode.onFailure+"/"+test.outcome, func(t *testing.T) {
				reader := newPolicyMetricReader(t)
				evaluator, err := New(Config{
					Mode:   mode.policy,
					Socket: &SocketConfig{APIURL: "https://api.socket.dev", Organization: testOrganization, Token: testToken}, OnFailure: mode.onFailure,
				})
				assert.NoError(t, err)
				inner := evaluator.(*metricsEvaluator).Evaluator
				if mode.onFailure == "deny" {
					inner = inner.(failClosedEvaluator).Evaluator
				}
				client := inner.(*socketEvaluator)
				client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.response))}, nil
				})

				decision, err := evaluator.Evaluate(t.Context(), testPURL)
				assert.Equal(t, test.outcome == "unavailable", err != nil)
				assert.Equal(t, mode.policy == ModeAudit, decision.Audit)
				outcome := test.outcome
				if mode.onFailure == "deny" && (outcome == "unavailable" || outcome == "pending") {
					outcome = "deny"
				}
				response := httptest.NewRecorder()
				assert.Equal(t, mode.policy == ModeAudit || outcome != "deny", AllowRequest(response, decision, err))
				if mode.policy == ModeAudit {
					if outcome == "deny" {
						outcome = "would_deny"
					} else {
						outcome = "would_allow"
					}
					assert.True(t, Cacheable(decision, err))
					assert.Equal(t, "audit-"+outcome, response.Header().Get(policyHeader))
					assert.Equal(t, "", response.Header().Get("Cache-Control"))
				} else if outcome == "deny" {
					assert.Equal(t, http.StatusForbidden, response.Code)
				}
				counts, durations := collectPolicyMetrics(t, reader)
				assert.Equal(t, map[string]int64{outcome: 1}, counts)
				assert.Equal(t, map[string]uint64{test.outcome: 1}, durations)
			})
		}
	}
}

func TestNewIgnoresCanceledRequestMetrics(t *testing.T) {
	reader := newPolicyMetricReader(t)
	evaluator, err := New(Config{
		Mode:         "enforce",
		OnFailure:    "allow",
		VerdictTTL:   time.Minute,
		ExcludePURLs: []string{"pkg:npm/@private/*"},
		Socket:       &SocketConfig{APIURL: "https://api.socket.dev", Organization: testOrganization, Token: testToken},
	})
	assert.NoError(t, err)
	client := evaluator.(*metricsEvaluator).Evaluator.(*excludingEvaluator).Evaluator.(*cachingEvaluator).Evaluator.(*socketEvaluator)
	var requests atomic.Int32
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(testAllowResponse))}, nil
	})
	decision, err := evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)

	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("package request abandoned")
	cancel(cause)
	for _, test := range []struct {
		purl            string
		originalVerdict Verdict
		cacheHit        bool
	}{
		{testPURL, VerdictAllow, true},
		{"pkg:npm/%40private/package@1.0.0", VerdictNotApplicable, false},
		{"pkg:npm/uncached@1.0.0", "", false},
	} {
		decision, err = evaluator.Evaluate(ctx, test.purl)
		assert.IsError(t, err, cause)
		assert.Equal(t, VerdictDeny, decision.Verdict)
		assert.Equal(t, test.originalVerdict, decision.OriginalVerdict)
		assert.Equal(t, test.cacheHit, decision.VerdictCacheHit)
		assert.False(t, AllowRequest(httptest.NewRecorder(), decision, err))
	}
	evaluator.ObserveNotApplicable(ctx)
	assert.Equal(t, int32(1), requests.Load())
	counts, durations := collectPolicyMetrics(t, reader)
	assert.Equal(t, map[string]int64{"allow": 1}, counts)
	assert.Equal(t, map[string]uint64{"allow": 1}, durations)
}

func TestAuditMetricsReportEffectiveWouldOutcomes(t *testing.T) {
	reader := newPolicyMetricReader(t)
	metrics := newMetrics()
	inner := &scriptedEvaluator{
		decisions: []Decision{{Verdict: VerdictDeny}, {Verdict: VerdictPending}, {}, {Verdict: VerdictNotApplicable}},
		errs:      []error{nil, nil, errors.New("socket down")},
	}
	evaluator := &metricsEvaluator{Evaluator: inner, metrics: metrics, audit: true}
	for range 4 {
		decision, err := evaluator.Evaluate(t.Context(), testPURL)
		assert.True(t, decision.Audit)
		assert.True(t, AllowRequest(httptest.NewRecorder(), decision, err))
		assert.True(t, Cacheable(decision, err))
	}
	counts, _ := collectPolicyMetrics(t, reader)
	assert.Equal(t, map[string]int64{"would_deny": 1, "would_allow": 2, "not_applicable": 1}, counts)
}

func TestOverloadMetricsRemainDistinctFromProviderUnavailable(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		t.Run(mode, func(t *testing.T) {
			reader := newPolicyMetricReader(t)
			inner := &scriptedEvaluator{decisions: []Decision{{Verdict: VerdictDeny}}, errs: []error{ErrOverloaded}}
			evaluator := &metricsEvaluator{Evaluator: inner, metrics: newMetrics(), audit: mode == ModeAudit}
			_, err := evaluator.Evaluate(t.Context(), testPURL)
			assert.IsError(t, err, ErrOverloaded)
			outcome := "overloaded"
			if mode == "audit" {
				outcome = "would_deny"
			}
			counts, durations := collectPolicyMetrics(t, reader)
			assert.Equal(t, map[string]int64{outcome: 1}, counts)
			assert.Equal(t, 0, len(durations))
		})
	}
}

func TestOperationalMetricsUseBoundedAttributes(t *testing.T) {
	reader := newPolicyMetricReader(t)
	metrics := newMetrics()
	metrics.recordDuration(t.Context(), Decision{Verdict: VerdictAllow}, nil, time.Second)
	metrics.recordQueueWait(t.Context(), time.Millisecond)
	metrics.recordInflight(t.Context(), 1)
	metrics.recordInflight(t.Context(), -1)
	metrics.recordCacheLookup(t.Context(), false)
	metrics.recordCacheLookup(t.Context(), true)
	metrics.recordBreakerSkip(t.Context())
	var resource metricdata.ResourceMetrics
	assert.NoError(t, reader.Collect(t.Context(), &resource))
	values := map[string]int64{}
	for _, scope := range resource.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			switch data := measurement.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					name := measurement.Name
					attrs := []attribute.KeyValue{attribute.String("provider", "socket")}
					switch measurement.Name {
					case "cachew.package_policy.verdict_cache_total":
						result, _ := point.Attributes.Value("result")
						name += "/" + result.AsString()
						attrs = append(attrs, attribute.String("result", result.AsString()))
					case "cachew.package_policy.provider_calls_total":
						attrs = append(attrs, attribute.String("outcome", "allow"))
					}
					assert.Equal(t, attribute.NewSet(attrs...), point.Attributes)
					values[name] = point.Value
				}
			case metricdata.Histogram[float64]:
				for _, point := range data.DataPoints {
					assert.Equal(t, uint64(1), point.Count)
					values[measurement.Name] = int64(point.Count)
				}
			default:
				t.Fatalf("unexpected operational metric: %s", measurement.Name)
			}
		}
	}
	assert.Equal(t, map[string]int64{
		"cachew.package_policy.provider_calls_total":        1,
		"cachew.package_policy.evaluation_duration_seconds": 1,
		"cachew.package_policy.queue_wait_seconds":          1,
		"cachew.package_policy.inflight":                    0,
		"cachew.package_policy.verdict_cache_total/hit":     1,
		"cachew.package_policy.verdict_cache_total/miss":    1,
		"cachew.package_policy.breaker_skips_total":         1,
	}, values)
}

func newPolicyMetricReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		assert.NoError(t, provider.Shutdown(context.Background()))
	})
	return reader
}

func collectPolicyMetrics(t *testing.T, reader *sdkmetric.ManualReader) (map[string]int64, map[string]uint64) {
	t.Helper()
	var resource metricdata.ResourceMetrics
	assert.NoError(t, reader.Collect(t.Context(), &resource))
	counts := map[string]int64{}
	durations := map[string]uint64{}
	for _, scope := range resource.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			if measurement.Name != "cachew.package_policy.evaluations_total" && measurement.Name != "cachew.package_policy.evaluation_duration_seconds" {
				continue
			}
			switch data := measurement.Data.(type) {
			case metricdata.Sum[int64]:
				assert.Equal(t, "cachew.package_policy.evaluations_total", measurement.Name)
				for _, point := range data.DataPoints {
					outcome, _ := point.Attributes.Value("outcome")
					assert.Equal(t, attribute.NewSet(attribute.String("provider", "socket"), attribute.String("outcome", outcome.AsString())), point.Attributes)
					counts[outcome.AsString()] += point.Value
				}
			case metricdata.Histogram[float64]:
				assert.Equal(t, "cachew.package_policy.evaluation_duration_seconds", measurement.Name)
				for _, point := range data.DataPoints {
					outcome, _ := point.Attributes.Value("outcome")
					assert.Equal(t, attribute.NewSet(attribute.String("provider", "socket"), attribute.String("outcome", outcome.AsString())), point.Attributes)
					durations[outcome.AsString()] += point.Count
				}
			default:
				t.Fatalf("unexpected package policy metric: %s", measurement.Name)
			}
		}
	}
	return counts, durations
}
