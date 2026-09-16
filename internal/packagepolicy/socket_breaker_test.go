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

func TestClientRechecksBreakerBeforeRetrying(t *testing.T) {
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
	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	ownerCtx, cancelOwner := context.WithCancel(t.Context())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := client.Evaluate(ownerCtx, testPURL)
		ownerResult <- err
	}()
	<-firstStarted

	waiterJoined := make(chan struct{})
	waiterCtx := &doneObservedContext{Context: t.Context(), observed: waiterJoined}
	waiterResult := make(chan error, 1)
	go func() {
		_, err := client.Evaluate(waiterCtx, testPURL)
		waiterResult <- err
	}()
	<-waiterJoined
	client.breaker.mu.Lock()
	client.breaker.openUntil = now.Add(breakerCooldown)
	client.breaker.mu.Unlock()
	cancelOwner()

	assert.True(t, errors.Is(<-ownerResult, context.Canceled))
	assert.IsError(t, <-waiterResult, ErrCircuitOpen)
	assert.Equal(t, int32(1), requests.Load())
}

func TestBreakerResetsFailureCountOnSuccess(t *testing.T) {
	now := time.Now()
	breaker := circuitBreaker{now: func() time.Time { return now }}
	down := markUnavailable(errors.New("dial Socket API"))
	for range breakerFailureThreshold - 1 {
		breaker.observe(down)
	}
	breaker.observe(nil)
	for range breakerFailureThreshold - 1 {
		breaker.observe(down)
	}
	assert.True(t, breaker.allow())

	breaker.observe(down)
	assert.False(t, breaker.allow())
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
	evaluator := &metricsEvaluator{Evaluator: client, metrics: metrics}
	now := time.Now()
	client.breaker.now = func() time.Time { return now }

	for range breakerFailureThreshold {
		_, err := evaluator.Evaluate(t.Context(), testPURL)
		assert.Error(t, err)
	}
	assert.Equal(t, int32(breakerFailureThreshold), requests.Load())

	_, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.IsError(t, err, ErrCircuitOpen)
	assert.Equal(t, int32(breakerFailureThreshold), requests.Load())
	assert.Equal(t, int32(breakerFailureThreshold+1), metrics.outcomes.Load())
	assert.Equal(t, int32(breakerFailureThreshold), metrics.evaluations.Load())

	now = now.Add(breakerCooldown)
	_, err = evaluator.Evaluate(t.Context(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, int32(breakerFailureThreshold+1), requests.Load())
	assert.Equal(t, int32(breakerFailureThreshold+2), metrics.outcomes.Load())
	assert.Equal(t, int32(breakerFailureThreshold+1), metrics.evaluations.Load())
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

func TestClientSkipsQueuedEvaluationsAfterCircuitOpens(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	client.callSlots = make(chan struct{}, 1)
	metrics := &recordingMetrics{}
	client.metrics = metrics
	evaluator := &metricsEvaluator{Evaluator: client, metrics: metrics}
	started := make(chan struct{})
	release := make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseAll)
	var requests atomic.Int32
	providerErr := errors.New("provider unavailable")
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == breakerFailureThreshold {
			close(started)
			<-release
		}
		return nil, providerErr
	})
	for range breakerFailureThreshold - 1 {
		_, err := evaluator.Evaluate(t.Context(), testPURL)
		assert.True(t, errors.Is(err, providerErr))
	}
	ownerResult := make(chan error, 1)
	go func() {
		_, err := evaluator.Evaluate(t.Context(), testPURL)
		ownerResult <- err
	}()
	<-started

	const waiters = 4
	results := make(chan error, waiters)
	for i := range waiters {
		joined := make(chan struct{})
		ctx := &doneObservedContext{Context: t.Context(), observed: joined}
		go func() {
			_, err := evaluator.Evaluate(ctx, fmt.Sprintf("pkg:npm/queued-%d@1.0.0", i/2))
			results <- err
		}()
		<-joined
	}
	releaseAll()
	assert.True(t, errors.Is(<-ownerResult, providerErr))
	for range waiters {
		assert.IsError(t, <-results, ErrCircuitOpen)
	}
	assert.Equal(t, int32(breakerFailureThreshold), requests.Load())
	assert.Equal(t, int32(breakerFailureThreshold), metrics.evaluations.Load())
	assert.Equal(t, int32(breakerFailureThreshold+waiters), metrics.outcomes.Load())
}
