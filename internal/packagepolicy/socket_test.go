package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

const (
	testOrganization  = "example-org"
	testToken         = "socket-test-token"
	testPURL          = "pkg:npm/chromatitle-js@1.0.0"
	testAllowResponse = `{"type":"npm","name":"chromatitle-js","version":"1.0.0","alerts":[]}`
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
		_, _ = w.Write([]byte(testAllowResponse))
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
	evaluator, err := New(Config{Socket: &SocketConfig{Organization: testOrganization, Token: testToken}})
	assert.NoError(t, err)
	assert.NotZero(t, evaluator)

	_, err = New(Config{})
	assert.Error(t, err)
}

func TestNewExcludesPURLsBeforeProviderEvaluation(t *testing.T) {
	var requests atomic.Int32
	evaluator, err := New(Config{
		ExcludePURLs: []string{"pkg:npm/%40pplx-internal/*", "pkg:pypi/pplx-*@*"},
		Socket: &SocketConfig{
			APIURL:       "https://socket.example.com",
			Organization: testOrganization,
			Token:        testToken,
		},
	})
	assert.NoError(t, err)
	excluding := evaluator.(*excludingEvaluator)
	socket := excluding.Evaluator.(*socketEvaluator)
	metrics := &recordingMetrics{}
	socket.metrics = metrics
	socket.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected Socket request")
	})

	for _, purl := range []string{
		"pkg:npm/%40pplx-internal/agents@1.2.3",
		"pkg:pypi/pplx-sdk@0.4.0",
	} {
		decision, err := evaluator.Evaluate(t.Context(), purl)
		assert.NoError(t, err)
		assert.Equal(t, VerdictNotApplicable, decision.Verdict)
	}
	assert.Equal(t, int32(0), requests.Load())
	assert.Equal(t, int32(2), metrics.notApplicable.Load())

	_, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, int32(1), requests.Load())
}

func TestNewRejectsInvalidExclusionPatterns(t *testing.T) {
	for _, pattern := range []string{"pkg:npm/[", "pkg:golang/github.com/ppl-ai/*"} {
		_, err := New(Config{
			ExcludePURLs: []string{pattern},
			Socket:       &SocketConfig{Organization: testOrganization, Token: testToken},
		})
		assert.Error(t, err)
	}
}

func TestClientEvaluatesOrganizationPolicy(t *testing.T) {
	tests := []struct {
		name     string
		response string
		verdict  Verdict
		reasons  []string
	}{
		{
			name:     "allows policy-approved package",
			response: `{"type":"npm","name":"lodash","version":"4.17.21","alerts":[{"type":"unpopularPackage","action":"monitor"}]}`,
			verdict:  VerdictAllow,
		},
		{
			name:     "denies policy error",
			response: `{"type":"npm","name":"chromatitle-js","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`,
			verdict:  VerdictDeny,
			reasons:  []string{"malware"},
		},
		{
			name:     "waits for pending analysis",
			response: `{"type":"npm","name":"new-package","version":"1.0.0","alerts":[{"type":"pendingScan","action":"ignore"}]}`,
			verdict:  VerdictPending,
			reasons:  []string{"pendingScan"},
		},
		{
			name:     "denies unscanned package",
			response: `{"type":"npm","name":"unknown-package","version":"1.0.0","alerts":[{"type":"notFound","action":"ignore"}]}`,
			verdict:  VerdictDeny,
			reasons:  []string{"notFound"},
		},
		{
			name: "denies if any package artifact is blocked",
			response: `{"type":"pypi","name":"example","version":"1.0.0","release":"py3-none-any-whl","alerts":[]}
{"type":"pypi","name":"example","version":"1.0.0","release":"tar-gz","alerts":[{"type":"malware","action":"error"}]}`,
			verdict: VerdictDeny,
			reasons: []string{"malware"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/v0/orgs/example-org/purl", r.URL.Path)
				assert.Equal(t, "Bearer "+testToken, r.Header.Get("Authorization"))
				assert.Equal(t, "true", r.URL.Query().Get("alerts"))
				assert.Equal(t, "true", r.URL.Query().Get("compact"))
				assert.Equal(t, "true", r.URL.Query().Get("poll"))
				assert.Equal(t, "false", r.URL.Query().Get("purlErrors"))
				assert.Equal(t, "30", r.URL.Query().Get("timeoutSec"))

				var body struct {
					Components []struct {
						PURL string `json:"purl"`
					} `json:"components"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Equal(t, testPURL, body.Components[0].PURL)
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = w.Write([]byte(test.response + "\n"))
			}))
			t.Cleanup(server.Close)

			client, err := newSocketEvaluator(SocketConfig{
				APIURL:       server.URL,
				Organization: testOrganization,
				Token:        testToken,
				Timeout:      30 * time.Second,
			}, true)
			assert.NoError(t, err)

			decision, err := client.Evaluate(context.Background(), testPURL)
			assert.NoError(t, err)
			assert.Equal(t, test.verdict, decision.Verdict)
			assert.Equal(t, test.reasons, decision.Reasons)
		})
	}
}

func TestClientCoalescesConcurrentEvaluations(t *testing.T) {
	metrics := &recordingMetrics{}
	harness := newBlockedSocketTestHarness(t, metrics)

	type result struct {
		decision Decision
		err      error
	}
	const callers = 16
	begin := make(chan struct{})
	results := make(chan result, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-begin
			decision, err := harness.client.Evaluate(t.Context(), testPURL)
			results <- result{decision: decision, err: err}
		}()
	}
	ready.Wait()
	close(begin)
	<-harness.started
	time.Sleep(25 * time.Millisecond)
	requestCount := harness.requests.Load()
	close(harness.release)
	assert.Equal(t, int32(1), requestCount)

	for range callers {
		evaluation := <-results
		assert.NoError(t, evaluation.err)
		assert.Equal(t, VerdictAllow, evaluation.decision.Verdict)
	}
	assert.Equal(t, int32(1), metrics.evaluations.Load())

	decision, err := harness.client.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
	assert.Equal(t, int32(2), harness.requests.Load())
	assert.Equal(t, int32(2), metrics.evaluations.Load())
}

func TestClientRecordsSharedEvaluationAfterCallerCancellation(t *testing.T) {
	metrics := &recordingMetrics{recorded: make(chan struct{}, 1)}
	harness := newBlockedSocketTestHarness(t, metrics)

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := harness.client.Evaluate(ctx, testPURL)
		result <- err
	}()
	<-harness.started
	cancel()
	assert.True(t, errors.Is(<-result, context.Canceled))
	assert.Equal(t, int32(0), metrics.evaluations.Load())
	close(harness.release)
	<-metrics.recorded
	assert.Equal(t, int32(1), metrics.evaluations.Load())
}

func TestClientFailsClosedOnInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
	}{
		{name: "upstream failure", statusCode: http.StatusTooManyRequests},
		{name: "malformed stream", statusCode: http.StatusOK, response: `{"type":`},
		{name: "empty stream", statusCode: http.StatusOK},
		{name: "unknown policy action", statusCode: http.StatusOK, response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"future-action"}]}`},
		{name: "mismatched PURL", statusCode: http.StatusOK, response: `{"inputPurl":"pkg:npm/other@1.0.0","type":"npm","name":"other","version":"1.0.0","alerts":[]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.response))
			}))
			t.Cleanup(server.Close)
			client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
			assert.NoError(t, err)

			_, err = client.Evaluate(context.Background(), testPURL)
			assert.Error(t, err)
		})
	}
}

func TestClientPreservesTransportFailureForCallerLogging(t *testing.T) {
	transportErr := errors.New("dial Socket API")
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	client.httpClient.Transport = roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, transportErr
	})

	_, err = client.Evaluate(context.Background(), testPURL)
	assert.True(t, errors.Is(err, transportErr))
}

func TestClientDoesNotForwardTokenAcrossRedirects(t *testing.T) {
	redirectRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectRequests++
		_, _ = w.Write([]byte(`{"type":"npm","name":"example","version":"1.0.0","alerts":[]}`))
	}))
	t.Cleanup(target.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)

	_, err = client.Evaluate(context.Background(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, 0, redirectRequests)
}
