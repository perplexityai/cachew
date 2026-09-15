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
	for _, mode := range []string{"allow", "deny"} {
		for _, test := range tests {
			t.Run(mode+"/"+test.outcome, func(t *testing.T) {
				reader := newPolicyMetricReader(t)
				evaluator, err := New(Config{
					Socket: &SocketConfig{APIURL: "https://api.socket.dev", Organization: testOrganization, Token: testToken}, OnFailure: mode,
				})
				assert.NoError(t, err)
				inner := evaluator.(*metricsEvaluator).Evaluator
				if mode == "deny" {
					inner = inner.(failClosedEvaluator).Evaluator
				}
				client := inner.(*socketEvaluator)
				client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.response))}, nil
				})

				decision, err := evaluator.Evaluate(t.Context(), testPURL)
				assert.Equal(t, test.outcome == "unavailable", err != nil)
				outcome := test.outcome
				if mode == "deny" && (outcome == "unavailable" || outcome == "pending") {
					outcome = "deny"
				}
				response := httptest.NewRecorder()
				assert.Equal(t, outcome != "deny", AllowRequest(response, decision, err))
				if outcome == "deny" {
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
	for _, purl := range []string{testPURL, "pkg:npm/%40private/package@1.0.0", "pkg:npm/uncached@1.0.0"} {
		decision, err = evaluator.Evaluate(ctx, purl)
		assert.IsError(t, err, cause)
		assert.Equal(t, VerdictDeny, decision.Verdict)
		assert.False(t, AllowRequest(httptest.NewRecorder(), decision, err))
	}
	evaluator.ObserveNotApplicable(ctx)
	assert.Equal(t, int32(1), requests.Load())
	counts, durations := collectPolicyMetrics(t, reader)
	assert.Equal(t, map[string]int64{"allow": 1}, counts)
	assert.Equal(t, map[string]uint64{"allow": 1}, durations)
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
