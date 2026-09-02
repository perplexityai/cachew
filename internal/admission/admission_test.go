package admission_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/admission"
)

const admissionTestTimeout = 2 * time.Second

func observeAdmissionPeak(peak *atomic.Int64, current int64) {
	for previous := peak.Load(); current > previous; previous = peak.Load() {
		if peak.CompareAndSwap(previous, current) {
			return
		}
	}
}

func startAdmissionRequest(handler http.Handler, path string) <-chan int {
	result := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		result <- w.Code
	}()
	return result
}

func waitForAdmission(t *testing.T, entered <-chan string) string {
	t.Helper()
	select {
	case path := <-entered:
		return path
	case <-time.After(admissionTestTimeout):
		t.Fatal("request did not enter the wrapped handler")
		return ""
	}
}

func waitForAdmissionResult(t *testing.T, result <-chan int) int {
	t.Helper()
	select {
	case status := <-result:
		return status
	case <-time.After(admissionTestTimeout):
		t.Fatal("admitted request did not complete")
		return 0
	}
}

func TestAdmissionRejectsWithoutQueueingAndReservesProtectedCapacity(t *testing.T) {
	limiter, err := admission.New(admission.Config{Limit: 3, Reserved: 1})
	assert.NoError(t, err)
	entered := make(chan string, 3)
	release := make(chan struct{})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.URL.Path
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	first := startAdmissionRequest(handler, "/artifact/first")
	second := startAdmissionRequest(handler, "/artifact/second")
	waitForAdmission(t, entered)
	waitForAdmission(t, entered)

	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, httptest.NewRequest(http.MethodGet, "/artifact/third", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rejected.Code)
	assert.Equal(t, "1", rejected.Header().Get("Retry-After"))

	readiness := startAdmissionRequest(handler, "/_readiness")
	assert.Equal(t, "/_readiness", waitForAdmission(t, entered))
	protectedRejected := httptest.NewRecorder()
	handler.ServeHTTP(protectedRejected, httptest.NewRequest(http.MethodGet, "/admin/pprof/heap", nil))
	assert.Equal(t, http.StatusServiceUnavailable, protectedRejected.Code)

	close(release)
	assert.Equal(t, http.StatusNoContent, waitForAdmissionResult(t, first))
	assert.Equal(t, http.StatusNoContent, waitForAdmissionResult(t, second))
	assert.Equal(t, http.StatusNoContent, waitForAdmissionResult(t, readiness))

	afterDrain := httptest.NewRecorder()
	handler.ServeHTTP(afterDrain, httptest.NewRequest(http.MethodGet, "/artifact/after-drain", nil))
	assert.Equal(t, http.StatusNoContent, afterDrain.Code)
}

func TestAdmissionProtectsHealthAndOperatorRoutesOnly(t *testing.T) {
	protectedPaths := []string{"/_liveness", "/_readiness", "/admin/log/level", "/admin/pprof/heap"}
	for _, path := range protectedPaths {
		t.Run(path, func(t *testing.T) {
			limiter, err := admission.New(admission.Config{Limit: 2, Reserved: 1})
			assert.NoError(t, err)
			entered := make(chan string, 2)
			release := make(chan struct{})
			handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- r.URL.Path
				<-release
				w.WriteHeader(http.StatusNoContent)
			}))

			normal := startAdmissionRequest(handler, "/artifact")
			waitForAdmission(t, entered)
			protected := startAdmissionRequest(handler, path)
			assert.Equal(t, path, waitForAdmission(t, entered))
			close(release)
			assert.Equal(t, http.StatusNoContent, waitForAdmissionResult(t, normal))
			assert.Equal(t, http.StatusNoContent, waitForAdmissionResult(t, protected))
		})
	}

	limiter, err := admission.New(admission.Config{Limit: 2, Reserved: 1})
	assert.NoError(t, err)
	release := make(chan struct{})
	entered := make(chan string, 1)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.URL.Path
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	held := startAdmissionRequest(handler, "/artifact")
	waitForAdmission(t, entered)
	for _, path := range []string{"/administer", "http://example.com/admin/artifact"} {
		result := startAdmissionRequest(handler, path)
		select {
		case status := <-result:
			assert.Equal(t, http.StatusServiceUnavailable, status)
		case admitted := <-entered:
			close(release)
			t.Fatalf("normal path %q consumed protected capacity", admitted)
		case <-time.After(admissionTestTimeout):
			close(release)
			t.Fatalf("normal path %q neither entered nor rejected", path)
		}
	}
	close(release)
	assert.Equal(t, http.StatusNoContent, waitForAdmissionResult(t, held))
}

func TestAdmissionConfigValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		config admission.Config
	}{
		{name: "NegativeLimit", config: admission.Config{Limit: -1}},
		{name: "NegativeReserve", config: admission.Config{Limit: 2, Reserved: -1}},
		{name: "ReserveWithoutLimit", config: admission.Config{Reserved: 1}},
		{name: "ReserveEqualsLimit", config: admission.Config{Limit: 2, Reserved: 2}},
		{name: "ReserveExceedsLimit", config: admission.Config{Limit: 2, Reserved: 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := admission.New(test.config)
			assert.Error(t, err)
		})
	}
}

func TestAdmissionDisabledPassesThrough(t *testing.T) {
	limiter, err := admission.New(admission.Config{})
	assert.NoError(t, err)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/artifact", nil))
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestAdmissionConcurrentRequestsStayWithinLimits(t *testing.T) {
	const (
		limit        = 8
		reserved     = 2
		requestCount = 64
	)
	limiter, err := admission.New(admission.Config{Limit: limit, Reserved: reserved})
	assert.NoError(t, err)
	entered := make(chan struct{}, limit)
	release := make(chan struct{})
	var activeTotal atomic.Int64
	var activeNormal atomic.Int64
	var peakTotal atomic.Int64
	var peakNormal atomic.Int64
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total := activeTotal.Add(1)
		observeAdmissionPeak(&peakTotal, total)
		normal := r.URL.Path != "/_readiness"
		if normal {
			observeAdmissionPeak(&peakNormal, activeNormal.Add(1))
		}
		entered <- struct{}{}
		<-release
		if normal {
			activeNormal.Add(-1)
		}
		activeTotal.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	}))

	start := make(chan struct{})
	results := make(chan int, requestCount)
	var wait sync.WaitGroup
	for index := range requestCount {
		wait.Go(func() {
			<-start
			path := "/artifact"
			if index%2 == 0 {
				path = "/_readiness"
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			results <- response.Code
		})
	}
	close(start)
	for range limit {
		select {
		case <-entered:
		case <-time.After(admissionTestTimeout):
			t.Fatal("admission did not fill configured capacity")
		}
	}
	for range requestCount - limit {
		select {
		case status := <-results:
			assert.Equal(t, http.StatusServiceUnavailable, status)
		case <-time.After(admissionTestTimeout):
			t.Fatal("saturated request did not fail without queueing")
		}
	}
	close(release)
	wait.Wait()
	for range limit {
		assert.Equal(t, http.StatusNoContent, <-results)
	}

	assert.True(t, peakTotal.Load() <= limit)
	assert.True(t, peakNormal.Load() <= limit-reserved)
	assert.Equal(t, int64(0), activeTotal.Load())
	assert.Equal(t, int64(0), activeNormal.Load())
}
