package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type blockingMetricRecorder struct {
	recordingMetrics
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (r *blockingMetricRecorder) recordDuration(context.Context, Decision, error, time.Duration) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
}

type doneObservedContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *doneObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

const (
	testOrganization  = "example-org"
	testToken         = "socket-test-token"
	testPURL          = "pkg:npm/chromatitle-js@1.0.0"
	testAllowResponse = `{"type":"npm","name":"chromatitle-js","version":"1.0.0","alerts":[]}`
	testDenyResponse  = `{"type":"npm","name":"chromatitle-js","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`
)

type blockedSocketTestHarness struct {
	client   *socketEvaluator
	requests atomic.Int32
	started  chan struct{}
	release  chan struct{}
}

func newBlockedSocketTestHarness(t *testing.T, metrics metricRecorder) *blockedSocketTestHarness {
	t.Helper()
	harness := &blockedSocketTestHarness{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if harness.requests.Add(1) == 1 {
			close(harness.started)
		}
		<-harness.release
		_, _ = w.Write([]byte(testDenyResponse))
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       server.URL,
		Organization: testOrganization,
		Token:        testToken,
	}, true)
	assert.NoError(t, err)
	client.metrics = metrics
	harness.client = client
	return harness
}

func TestNewSelectsSocketProvider(t *testing.T) {
	evaluator, err := New(Config{Mode: "enforce", OnFailure: "allow", Socket: &SocketConfig{APIURL: "https://api.socket.dev", Organization: testOrganization, Token: testToken}})
	assert.NoError(t, err)
	assert.NotZero(t, evaluator)

	_, err = New(Config{})
	assert.Error(t, err)
}

func TestNewExcludesPURLsBeforeProviderEvaluation(t *testing.T) {
	var requests atomic.Int32
	evaluator, err := New(Config{
		Mode:         "enforce",
		OnFailure:    "allow",
		ExcludePURLs: []string{"pkg:npm/%40pplx-internal/*", "pkg:npm/@pplx-private/*"},
		Socket: &SocketConfig{
			APIURL:       "https://socket.example.com",
			Organization: testOrganization,
			Token:        testToken,
		},
	})
	assert.NoError(t, err)
	measured := evaluator.(*metricsEvaluator)
	excluding := measured.Evaluator.(*excludingEvaluator)
	socket := excluding.Evaluator.(*socketEvaluator)
	metrics := &recordingMetrics{}
	socket.metrics = metrics
	measured.metrics = metrics
	socket.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected Socket request")
	})

	for _, purl := range []string{
		"pkg:npm/%40pplx-internal/agents@1.2.3",
		"pkg:npm/%40pplx-private/tools@2.0.0",
	} {
		decision, err := evaluator.Evaluate(t.Context(), purl)
		assert.NoError(t, err)
		assert.Equal(t, VerdictNotApplicable, decision.Verdict)
	}
	assert.Equal(t, int32(0), requests.Load())
	assert.Equal(t, int32(2), metrics.notApplicable.Load())
	assert.Equal(t, int32(2), metrics.outcomes.Load())
	assert.Equal(t, int32(0), metrics.evaluations.Load())

	_, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, int32(1), requests.Load())
	assert.Equal(t, int32(3), metrics.outcomes.Load())
}

func TestNewRejectsInvalidExclusionPatterns(t *testing.T) {
	for _, pattern := range []string{"pkg:npm/[", "pkg:pypi/private-*", "pkg:cargo/private-*", "pkg:maven/com.example/*", "pkg:golang/github.com/ppl-ai/*"} {
		_, err := New(Config{
			Mode:         "enforce",
			OnFailure:    "allow",
			ExcludePURLs: []string{pattern},
			Socket:       &SocketConfig{APIURL: "https://api.socket.dev", Organization: testOrganization, Token: testToken},
		})
		assert.Error(t, err)
	}
}

func TestNewDoesNotStackDecoratorErrorPrefixes(t *testing.T) {
	evaluator, err := New(Config{
		Mode:         "enforce",
		OnFailure:    "allow",
		ExcludePURLs: []string{"pkg:npm/@pplx-private/*"},
		VerdictTTL:   time.Minute,
		Socket:       &SocketConfig{APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken},
	})
	assert.NoError(t, err)
	socket := evaluator.(*metricsEvaluator).Evaluator.(*excludingEvaluator).Evaluator.(*cachingEvaluator).Evaluator.(*socketEvaluator)
	socket.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial Socket API")
	})

	_, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, 1, strings.Count(err.Error(), "package policy: evaluate provider"))
}
