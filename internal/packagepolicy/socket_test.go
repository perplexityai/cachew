package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type blockingMetricRecorder struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (r *blockingMetricRecorder) record(context.Context, Decision, error, time.Duration) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
}

func (*blockingMetricRecorder) recordNotApplicable(context.Context) {}

func (*blockingMetricRecorder) recordOutcome(context.Context, Decision, error) {}

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
		ExcludePURLs: []string{"pkg:npm/%40pplx-internal/*", "pkg:npm/@pplx-private/*", "pkg:pypi/pplx-*@*"},
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
		"pkg:npm/%40pplx-private/tools@2.0.0",
		"pkg:pypi/pplx-sdk@0.4.0",
	} {
		decision, err := evaluator.Evaluate(t.Context(), purl)
		assert.NoError(t, err)
		assert.Equal(t, VerdictNotApplicable, decision.Verdict)
	}
	assert.Equal(t, int32(0), requests.Load())
	assert.Equal(t, int32(3), metrics.notApplicable.Load())

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
			name:     "treats unscanned package as pending",
			response: `{"type":"npm","name":"unknown-package","version":"1.0.0","alerts":[{"type":"notFound","action":"ignore"}]}`,
			verdict:  VerdictPending,
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

func TestClientCancelsProviderAfterOnlyCallerCancels(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	started := make(chan struct{})
	stopped := make(chan struct{})
	client.httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		close(stopped)
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := client.Evaluate(ctx, testPURL)
		result <- err
	}()
	<-started
	cancel()
	assert.True(t, errors.Is(<-result, context.Canceled))
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("provider request continued after its only caller canceled")
	}
}

func TestClientRetriesWhenSharedEvaluationOwnerCancels(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	firstStarted := make(chan struct{})
	var requests atomic.Int32
	client.httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(firstStarted)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(testAllowResponse)),
		}, nil
	})

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := client.Evaluate(ownerCtx, testPURL)
		ownerResult <- err
	}()
	<-firstStarted

	waiterResult := make(chan error, 1)
	go func() {
		decision, err := client.Evaluate(t.Context(), testPURL)
		if err == nil && decision.Verdict != VerdictAllow {
			err = errors.Errorf("unexpected verdict %q", decision.Verdict)
		}
		waiterResult <- err
	}()
	time.Sleep(25 * time.Millisecond)
	cancelOwner()

	assert.True(t, errors.Is(<-ownerResult, context.Canceled))
	assert.NoError(t, <-waiterResult)
	assert.Equal(t, int32(2), requests.Load())
}

func TestClientPreservesCompletedDecisionWhenOwnerCancels(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	metrics := &blockingMetricRecorder{started: make(chan struct{}), release: make(chan struct{})}
	client.metrics = metrics
	var requests atomic.Int32
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) > 1 {
			return nil, errors.New("unexpected policy retry")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`,
			)),
		}, nil
	})

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := client.Evaluate(ownerCtx, testPURL)
		ownerResult <- err
	}()
	<-metrics.started

	waiterJoined := make(chan struct{})
	waiterCtx := &doneObservedContext{Context: t.Context(), observed: waiterJoined}
	type result struct {
		decision Decision
		err      error
	}
	waiterResult := make(chan result, 1)
	go func() {
		decision, err := client.Evaluate(waiterCtx, testPURL)
		waiterResult <- result{decision: decision, err: err}
	}()
	<-waiterJoined
	cancelOwner()
	assert.True(t, errors.Is(<-ownerResult, context.Canceled))
	close(metrics.release)

	evaluation := <-waiterResult
	assert.NoError(t, evaluation.err)
	assert.Equal(t, VerdictDeny, evaluation.decision.Verdict)
	assert.Equal(t, []string{"malware"}, evaluation.decision.Reasons)
	assert.Equal(t, int32(1), requests.Load())
}

func TestClientBoundsConcurrentProviderEvaluations(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	const limit = 2
	const callers = 8
	client.callSlots = make(chan struct{}, limit)
	started := make(chan struct{}, callers)
	release := make(chan struct{})
	var requests atomic.Int32
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		started <- struct{}{}
		<-release
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(testAllowResponse)),
		}, nil
	})

	results := make(chan error, callers)
	for i := range callers {
		go func() {
			_, err := client.Evaluate(t.Context(), fmt.Sprintf("pkg:npm/example-%d@1.0.0", i))
			results <- err
		}()
	}
	for range limit {
		<-started
	}
	time.Sleep(25 * time.Millisecond)
	assert.Equal(t, int32(limit), requests.Load())
	close(release)
	for range callers {
		assert.NoError(t, <-results)
	}
	assert.Equal(t, int32(callers), requests.Load())
}

func TestClientReportsInvalidResponsesAsErrors(t *testing.T) {
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

func TestClientPreservesErrorResponseReadFailure(t *testing.T) {
	readErr := errors.New("read Socket error response")
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Status:     http.StatusText(http.StatusTooManyRequests),
			Header:     make(http.Header),
			Body:       io.NopCloser(iotest.ErrReader(readErr)),
		}, nil
	})

	_, err = client.Evaluate(context.Background(), testPURL)
	assert.True(t, errors.Is(err, readErr))
}

func TestDenyDominatesLaterInvalidStreamData(t *testing.T) {
	denied := `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`
	tests := []struct {
		name     string
		response string
	}{
		{name: "malformed record", response: denied + "\n" + `{"type":`},
		{name: "unknown action record", response: denied + "\n" + `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"other","action":"future"}]}`},
		{name: "unknown action in denied record", response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"error"},{"type":"other","action":"future"}]}`},
		{name: "denial follows unknown action", response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"other","action":"future"},{"type":"malware","action":"error"}]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluateStream(strings.NewReader(test.response), testPURL)
			assert.NoError(t, err)
			assert.Equal(t, VerdictDeny, decision.Verdict)
			assert.Equal(t, []string{"malware"}, decision.Reasons)
		})
	}
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

func TestClientSkipsProviderWhileCircuitIsOpen(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)
	metrics := &recordingMetrics{}
	client.metrics = metrics
	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range breakerFailureThreshold {
		_, err := client.Evaluate(t.Context(), testPURL)
		assert.Error(t, err)
	}
	assert.Equal(t, int32(breakerFailureThreshold), requests.Load())

	_, err = client.Evaluate(t.Context(), testPURL)
	assert.IsError(t, err, ErrCircuitOpen)
	assert.Equal(t, int32(breakerFailureThreshold), requests.Load())
	assert.Equal(t, int32(1), metrics.outcomes.Load())

	now = now.Add(breakerCooldown)
	_, err = client.Evaluate(t.Context(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, int32(breakerFailureThreshold+1), requests.Load())
}

func TestClientBreakerIgnoresMalformedPackageResponses(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"type":`)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)

	for range breakerFailureThreshold + 1 {
		_, err := client.Evaluate(t.Context(), testPURL)
		assert.Error(t, err)
		assert.False(t, isProviderUnavailable(err))
	}
	assert.Equal(t, int32(breakerFailureThreshold+1), requests.Load())
}

func TestClientAcceptsPercentDecodedInputPURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"inputPurl":"pkg:npm/@ctrl/tinycolor@4.1.1","type":"npm","name":"@ctrl/tinycolor","version":"4.1.1","alerts":[]}`)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)

	decision, err := client.Evaluate(t.Context(), "pkg:npm/%40ctrl/tinycolor@4.1.1")
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
}

func TestClientQueuesForProviderSlot(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, testAllowResponse)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)
	client.callSlots = make(chan struct{}, 1)
	client.callSlots <- struct{}{}

	type result struct {
		decision Decision
		err      error
	}
	results := make(chan result, 1)
	go func() {
		decision, err := client.Evaluate(t.Context(), testPURL)
		results <- result{decision: decision, err: err}
	}()
	select {
	case got := <-results:
		t.Fatalf("evaluation finished while every provider slot was held: %+v", got)
	case <-time.After(25 * time.Millisecond):
	}
	assert.Equal(t, int32(0), requests.Load())

	<-client.callSlots
	got := <-results
	assert.NoError(t, got.err)
	assert.Equal(t, VerdictAllow, got.decision.Verdict)
	assert.Equal(t, int32(1), requests.Load())

	// A queued caller that gives up leaves without a provider call.
	client.callSlots <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = client.Evaluate(ctx, testPURL)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Equal(t, int32(1), requests.Load())
}
