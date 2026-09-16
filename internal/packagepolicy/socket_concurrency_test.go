package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"context"
	"fmt"
	"io"
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

func TestClientCoalescesConcurrentEvaluations(t *testing.T) {
	metrics := &recordingMetrics{}
	harness := newBlockedSocketTestHarness(t, metrics)
	evaluator := &metricsEvaluator{Evaluator: harness.client, metrics: metrics}

	type result struct {
		decision Decision
		err      error
	}
	const callers = 21
	results := make(chan result, callers)
	waiting := make([]*doneObservedContext, callers)
	for i := range callers {
		ctx := &doneObservedContext{Context: t.Context(), observed: make(chan struct{})}
		waiting[i] = ctx
		go func() {
			decision, err := evaluator.Evaluate(ctx, testPURL)
			results <- result{decision: decision, err: err}
		}()
	}
	<-harness.started
	for _, ctx := range waiting {
		<-ctx.observed
	}
	requestCount := harness.requests.Load()
	close(harness.release)
	assert.Equal(t, int32(1), requestCount)

	for range callers {
		evaluation := <-results
		assert.NoError(t, evaluation.err)
		assert.Equal(t, VerdictDeny, evaluation.decision.Verdict)
	}
	assert.Equal(t, int32(1), metrics.evaluations.Load())
	assert.Equal(t, int32(callers), metrics.outcomes.Load())

	decision, err := evaluator.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictDeny, decision.Verdict)
	assert.Equal(t, int32(2), harness.requests.Load())
	assert.Equal(t, int32(2), metrics.evaluations.Load())
	assert.Equal(t, int32(callers+1), metrics.outcomes.Load())
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
	type evaluation struct {
		decision Decision
		err      error
	}
	result := make(chan evaluation, 1)
	go func() {
		decision, err := client.Evaluate(ctx, testPURL)
		result <- evaluation{decision: decision, err: err}
	}()
	<-started
	cancel()
	got := <-result
	assert.True(t, errors.Is(got.err, context.Canceled))
	assert.Equal(t, VerdictDeny, got.decision.Verdict)
	w := httptest.NewRecorder()
	assert.False(t, AllowRequest(w, got.decision, got.err))
	assert.Equal(t, http.StatusForbidden, w.Code)
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

	metrics := &recordingMetrics{}
	client.metrics = metrics
	evaluator := &metricsEvaluator{Evaluator: client, metrics: metrics}

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := evaluator.Evaluate(ownerCtx, testPURL)
		ownerResult <- err
	}()
	<-firstStarted

	waiterJoined := make(chan struct{})
	waiterCtx := &doneObservedContext{Context: t.Context(), observed: waiterJoined}
	waiterResult := make(chan error, 1)
	go func() {
		decision, err := evaluator.Evaluate(waiterCtx, testPURL)
		if err == nil && decision.Verdict != VerdictAllow {
			err = errors.Errorf("unexpected verdict %q", decision.Verdict)
		}
		waiterResult <- err
	}()
	<-waiterJoined
	cancelOwner()

	assert.True(t, errors.Is(<-ownerResult, context.Canceled))
	assert.NoError(t, <-waiterResult)
	assert.Equal(t, int32(2), requests.Load())
	assert.Equal(t, int32(2), metrics.evaluations.Load())
	assert.Equal(t, int32(1), metrics.outcomes.Load())
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

func TestClientsShareConcurrentProviderLimit(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	otherClient, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	started := make(chan struct{}, maxConcurrentCalls+1)
	release := make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseAll)
	var requests atomic.Int32
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(testAllowResponse)),
		}, nil
	})
	client.httpClient.Transport = transport
	otherClient.httpClient.Transport = transport

	results := make(chan error, maxConcurrentCalls)
	for i := range maxConcurrentCalls {
		go func() {
			_, err := client.Evaluate(t.Context(), fmt.Sprintf("pkg:npm/example-%d@1.0.0", i))
			results <- err
		}()
	}
	for range maxConcurrentCalls {
		<-started
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = otherClient.Evaluate(ctx, testPURL)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	assert.Equal(t, int32(maxConcurrentCalls), requests.Load())
	releaseAll()
	for range maxConcurrentCalls {
		assert.NoError(t, <-results)
	}
	assert.Equal(t, int32(maxConcurrentCalls), requests.Load())
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
	client.queueTimeout = time.Minute
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

	client.callSlots <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = client.Evaluate(ctx, testPURL)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Equal(t, int32(1), requests.Load())
}

func TestClientCanceledQueueDoesNotFailOpen(t *testing.T) {
	for _, onFailure := range []string{string(VerdictAllow), string(VerdictDeny)} {
		t.Run(onFailure, func(t *testing.T) {
			client, err := newSocketEvaluator(SocketConfig{
				APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
			}, false)
			assert.NoError(t, err)
			metrics := &recordingMetrics{}
			client.metrics = metrics
			var requests atomic.Int32
			client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errors.New("unexpected provider request")
			})
			client.callSlots = make(chan struct{}, 1)
			client.callSlots <- struct{}{}
			var evaluator Evaluator = client
			if onFailure == string(VerdictDeny) {
				evaluator = failClosedEvaluator{Evaluator: evaluator}
			}
			evaluator = &metricsEvaluator{Evaluator: evaluator, metrics: metrics}
			ctx, cancel := context.WithCancelCause(t.Context())
			t.Cleanup(func() { cancel(context.Canceled) })
			const callers = breakerFailureThreshold + 1
			type evaluation struct {
				decision Decision
				err      error
			}
			results := make(chan evaluation, callers)
			for i := range callers {
				queued := make(chan struct{})
				requestCtx := &doneObservedContext{Context: ctx, observed: queued}
				go func() {
					decision, err := evaluator.Evaluate(requestCtx, fmt.Sprintf("pkg:npm/queued-%d@1.0.0", i))
					results <- evaluation{decision: decision, err: err}
				}()
				select {
				case <-queued:
				case <-time.After(time.Second):
					t.Fatal("request did not queue for a provider slot")
				}
			}
			assert.Equal(t, int32(0), requests.Load())
			cause := errors.New("request abandoned while queued")
			cancel(cause)
			for range callers {
				select {
				case got := <-results:
					assert.True(t, errors.Is(got.err, cause))
					assert.Equal(t, VerdictDeny, got.decision.Verdict)
					w := httptest.NewRecorder()
					assert.False(t, AllowRequest(w, got.decision, got.err))
					assert.Equal(t, http.StatusForbidden, w.Code)
				case <-time.After(time.Second):
					t.Fatal("canceled request remained queued")
				}
			}
			assert.Equal(t, int32(0), requests.Load())
			assert.True(t, client.breaker.allow())
			client.breaker.mu.Lock()
			failures := client.breaker.failures
			client.breaker.mu.Unlock()
			assert.Equal(t, 0, failures)
			assert.Equal(t, int32(0), metrics.outcomes.Load())
			assert.Equal(t, int32(0), metrics.evaluations.Load())
		})
	}
}

func TestClientProviderTimeoutUsesFailureMode(t *testing.T) {
	for _, onFailure := range []string{string(VerdictAllow), string(VerdictDeny)} {
		t.Run(onFailure, func(t *testing.T) {
			reader := newPolicyMetricReader(t)
			client, err := newSocketEvaluator(SocketConfig{
				APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
			}, false)
			assert.NoError(t, err)
			client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, context.DeadlineExceeded
			})
			var evaluator Evaluator = client
			if onFailure == string(VerdictDeny) {
				evaluator = failClosedEvaluator{Evaluator: evaluator}
			}
			evaluator = &metricsEvaluator{Evaluator: evaluator, metrics: client.metrics}
			decision, err := evaluator.Evaluate(t.Context(), testPURL)
			assert.True(t, errors.Is(err, context.DeadlineExceeded))
			assert.NoError(t, t.Context().Err())
			w := httptest.NewRecorder()
			assert.Equal(t, onFailure == "allow", AllowRequest(w, decision, err))
			outcome := outcomeUnavailable
			if onFailure == string(VerdictDeny) {
				outcome = string(VerdictDeny)
			}
			counts, durations := collectPolicyMetrics(t, reader)
			assert.Equal(t, map[string]int64{outcome: 1}, counts)
			assert.Equal(t, map[string]uint64{outcomeUnavailable: 1}, durations)
		})
	}
}

func TestClientRejectsQueueSaturationWithoutFailingOpen(t *testing.T) {
	for _, onFailure := range []string{string(VerdictAllow), string(VerdictDeny)} {
		t.Run(onFailure, func(t *testing.T) {
			client, err := newSocketEvaluator(SocketConfig{
				APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
				QueueTimeout: time.Millisecond,
			}, false)
			assert.NoError(t, err)
			metrics := &recordingMetrics{}
			client.metrics = metrics
			client.callSlots = make(chan struct{}, 1)
			client.callSlots <- struct{}{}
			client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				t.Error("queue overflow reached the provider")
				return nil, errors.New("unexpected provider request")
			})
			var evaluator Evaluator = client
			if onFailure == string(VerdictDeny) {
				evaluator = failClosedEvaluator{Evaluator: client}
			}
			for i := range breakerFailureThreshold + 1 {
				decision, err := evaluator.Evaluate(t.Context(), fmt.Sprintf("pkg:npm/overflow-%d@1.0.0", i))
				assert.IsError(t, err, ErrOverloaded)
				assert.False(t, errors.Is(err, context.DeadlineExceeded))
				assert.Equal(t, VerdictDeny, decision.Verdict)
				assert.False(t, Cacheable(decision, err))
				w := httptest.NewRecorder()
				assert.False(t, AllowRequest(w, decision, err))
				assert.Equal(t, http.StatusServiceUnavailable, w.Code)
			}
			assert.True(t, client.breaker.allow())
			assert.Equal(t, 0, client.breaker.failures)
			assert.Equal(t, int32(0), metrics.evaluations.Load())
		})
	}
}
