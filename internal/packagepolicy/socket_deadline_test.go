package packagepolicy //nolint:testpackage // White-box coverage is required for deadline and transport injection.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

const deadlineTestBudget = 10 * time.Second

type deadlineTestResult struct {
	decision Decision
	err      error
}

func evaluateDeadlineAsync(ctx context.Context, evaluator Evaluator) <-chan deadlineTestResult {
	result := make(chan deadlineTestResult, 1)
	go func() {
		decision, err := evaluator.Evaluate(ctx, testPURL)
		result <- deadlineTestResult{decision: decision, err: err}
	}()
	return result
}

func newDeadlineTestClient(t *testing.T, transport roundTripperFunc) (*socketEvaluator, *recordingMetrics) {
	t.Helper()
	client, err := newSocketEvaluator(SocketConfig{
		APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
		Timeout: deadlineTestBudget, QueueTimeout: 2 * deadlineTestBudget,
	}, false)
	assert.NoError(t, err)
	metrics := &recordingMetrics{}
	client.metrics = metrics
	client.httpClient.Transport = transport
	client.callSlots = make(chan struct{}, 1)
	return client, metrics
}

func TestSocketDeadlineIncludesQueueAndProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan time.Time, 1)
		client, metrics := newDeadlineTestClient(t, func(request *http.Request) (*http.Response, error) {
			deadline, _ := request.Context().Deadline()
			started <- deadline
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		client.callSlots <- struct{}{}
		start := time.Now()
		result := evaluateDeadlineAsync(t.Context(), client)
		synctest.Wait()
		time.Sleep(6 * time.Second)
		<-client.callSlots
		assert.Equal(t, start.Add(deadlineTestBudget), <-started)
		got := <-result
		synctest.Wait()
		assert.Equal(t, deadlineTestBudget, time.Since(start))
		assert.IsError(t, got.err, context.DeadlineExceeded)
		assert.False(t, errors.Is(got.err, ErrOverloaded))
		assert.Equal(t, Decision{}, got.decision)
		assert.NoError(t, t.Context().Err())
		assert.Equal(t, int32(1), metrics.evaluations.Load())
		assert.Equal(t, 1, client.breaker.failures)
		assert.Equal(t, 0, len(client.callSlots))
	})
}

func TestSocketDeadlineInterruptsProviderResponseBody(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, metrics := newDeadlineTestClient(t, func(request *http.Request) (*http.Response, error) {
			reader, writer := io.Pipe()
			go func() {
				<-request.Context().Done()
				_ = writer.CloseWithError(request.Context().Err())
			}()
			return &http.Response{StatusCode: http.StatusOK, Body: reader}, nil
		})
		start := time.Now()
		decision, err := client.Evaluate(t.Context(), testPURL)
		synctest.Wait()
		assert.Equal(t, deadlineTestBudget, time.Since(start))
		assert.IsError(t, err, context.DeadlineExceeded)
		assert.Equal(t, Decision{}, decision)
		assert.NoError(t, t.Context().Err())
		assert.Equal(t, int32(1), metrics.evaluations.Load())
		assert.Equal(t, 1, client.breaker.failures)
		assert.Equal(t, 0, len(client.callSlots))
	})
}

func TestSocketDeadlineDoesNotResetAfterSharedOwnerCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan time.Time, 2)
		client, metrics := newDeadlineTestClient(t, func(request *http.Request) (*http.Response, error) {
			deadline, _ := request.Context().Deadline()
			started <- deadline
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		ownerCtx, cancelOwner := context.WithCancel(t.Context())
		defer cancelOwner()
		ownerStart := time.Now()
		owner := evaluateDeadlineAsync(ownerCtx, client)
		assert.Equal(t, ownerStart.Add(deadlineTestBudget), <-started)
		time.Sleep(2 * time.Second)
		waiterStart := time.Now()
		waiter := evaluateDeadlineAsync(t.Context(), client)
		synctest.Wait()
		time.Sleep(4 * time.Second)
		cancelOwner()
		assert.IsError(t, (<-owner).err, context.Canceled)
		assert.Equal(t, waiterStart.Add(deadlineTestBudget), <-started)
		got := <-waiter
		synctest.Wait()
		assert.Equal(t, deadlineTestBudget, time.Since(waiterStart))
		assert.IsError(t, got.err, context.DeadlineExceeded)
		assert.Equal(t, Decision{}, got.decision)
		assert.NoError(t, t.Context().Err())
		assert.Equal(t, int32(2), metrics.evaluations.Load())
		assert.Equal(t, 1, client.breaker.failures)
		assert.Equal(t, 0, len(client.callSlots))
	})
}

func TestSocketSharedProviderDeadlineDoesNotRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{}, 2)
		client, metrics := newDeadlineTestClient(t, func(request *http.Request) (*http.Response, error) {
			started <- struct{}{}
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		start := time.Now()
		owner := evaluateDeadlineAsync(t.Context(), client)
		<-started
		time.Sleep(2 * time.Second)
		waiter := evaluateDeadlineAsync(t.Context(), client)
		synctest.Wait()
		assert.IsError(t, (<-owner).err, context.DeadlineExceeded)
		assert.IsError(t, (<-waiter).err, context.DeadlineExceeded)
		synctest.Wait()
		assert.Equal(t, deadlineTestBudget, time.Since(start))
		assert.Equal(t, int32(1), metrics.evaluations.Load())
		assert.Equal(t, 0, len(started))
		assert.Equal(t, 1, client.breaker.failures)
	})
}

func TestSocketDeadlineBeforeAdmissionRemainsOverload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, metrics := newDeadlineTestClient(t, func(*http.Request) (*http.Response, error) {
			t.Error("local capacity timeout reached the provider")
			return nil, errors.New("unexpected provider request")
		})
		client.callSlots <- struct{}{}
		start := time.Now()
		owner := evaluateDeadlineAsync(t.Context(), client)
		synctest.Wait()
		time.Sleep(2 * time.Second)
		waiter := evaluateDeadlineAsync(t.Context(), client)
		synctest.Wait()
		for _, result := range []<-chan deadlineTestResult{owner, waiter} {
			got := <-result
			assert.IsError(t, got.err, ErrOverloaded)
			assert.False(t, errors.Is(got.err, context.DeadlineExceeded))
			assert.Equal(t, VerdictDeny, got.decision.Verdict)
			assert.False(t, Cacheable(got.decision, got.err))
			response := httptest.NewRecorder()
			assert.False(t, AllowRequest(response, got.decision, got.err))
			assert.Equal(t, http.StatusServiceUnavailable, response.Code)
		}
		synctest.Wait()
		assert.Equal(t, deadlineTestBudget, time.Since(start))
		assert.NoError(t, t.Context().Err())
		assert.Equal(t, int32(0), metrics.evaluations.Load())
		assert.Equal(t, 0, client.breaker.failures)
		assert.True(t, client.breaker.allow())
	})
}

func TestSocketDeadlinePreservesFailureAndAuditModes(t *testing.T) {
	for _, mode := range []string{ModeEnforce, ModeAudit} {
		for _, onFailure := range []Verdict{VerdictAllow, VerdictDeny} {
			t.Run(mode+"/"+string(onFailure), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client, metrics := newDeadlineTestClient(t, func(request *http.Request) (*http.Response, error) {
						<-request.Context().Done()
						return nil, request.Context().Err()
					})
					var evaluator Evaluator = client
					if onFailure == VerdictDeny {
						evaluator = failClosedEvaluator{Evaluator: evaluator}
					}
					evaluator = &metricsEvaluator{Evaluator: evaluator, metrics: metrics, audit: mode == ModeAudit}
					start := time.Now()
					decision, err := evaluator.Evaluate(t.Context(), testPURL)
					synctest.Wait()
					assert.Equal(t, deadlineTestBudget, time.Since(start))
					assert.IsError(t, err, context.DeadlineExceeded)
					assert.NoError(t, t.Context().Err())
					assert.Equal(t, mode == ModeAudit, decision.Audit)
					assert.Equal(t, onFailure == VerdictDeny, decision.Verdict == VerdictDeny)
					assert.Equal(t, mode == ModeAudit, Cacheable(decision, err))
					response := httptest.NewRecorder()
					assert.Equal(t, mode == ModeAudit || onFailure == VerdictAllow, AllowRequest(response, decision, err))
					switch {
					case mode == ModeAudit:
						assert.Equal(t, "audit-would_"+string(onFailure), response.Header().Get(policyHeader))
					case onFailure == VerdictDeny:
						assert.Equal(t, http.StatusForbidden, response.Code)
					default:
						assert.Equal(t, outcomeUnavailable, response.Header().Get(policyHeader))
					}
					assert.Equal(t, int32(1), metrics.evaluations.Load())
					assert.Equal(t, int32(1), metrics.outcomes.Load())
				})
			})
		}
	}
}
