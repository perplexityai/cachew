package strategy //nolint:testpackage // Reuse the real HTTP and S3 cache-fill fixture.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/s3client/s3clienttest"
)

func TestCacheFillWaiterCancel(t *testing.T) {
	bucket := s3clienttest.Start(t)
	h := newCacheFillHarness(t, bucket, "codeartifact", "complete")
	h.disconnect(t, false)
	waitCacheFill(t, h.started)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+h.path, nil)
	assert.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := h.server.Client().Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	waitCacheFill(t, h.started)
	cancel()
	waitCacheFill(t, done)
	waitCacheFill(t, h.finished)
	assert.Equal(t, int32(1), h.originRequests.Load())
	h.release()
	waitCacheFill(t, h.finished)
	h.assertStored(t, false)
}

func TestCacheFillConcurrent(t *testing.T) {
	bucket := s3clienttest.Start(t)
	for _, scenario := range []string{"complete", "upload-failure"} {
		t.Run(scenario, func(t *testing.T) {
			h := newCacheFillHarness(t, bucket, "codeartifact", scenario)
			h.disconnect(t, false)
			waitCacheFill(t, h.started)
			const callers = 8
			results := make(chan string, callers)
			for range callers {
				go func() {
					resp, err := h.server.Client().Get(h.server.URL + h.path)
					if err != nil {
						results <- err.Error()
						return
					}
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						results <- err.Error()
						return
					}
					results <- string(body)
				}()
			}
			for range callers {
				waitCacheFill(t, h.started)
			}
			h.release()
			for range callers {
				select {
				case body := <-results:
					assert.Equal(t, h.body, body)
				case <-time.After(5 * time.Second):
					t.Fatal("waiting download did not complete")
				}
			}
			for range callers + 1 {
				waitCacheFill(t, h.finished)
			}
			want := int32(1)
			if scenario == "upload-failure" {
				want = callers + 1
				h.assertStored(t, true)
				h.failUpload.Store(false)
				resp, err := h.server.Client().Get(h.server.URL + h.path)
				assert.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.NoError(t, resp.Body.Close())
				assert.Equal(t, h.body, string(body))
				waitCacheFill(t, h.finished)
				want++
			}
			assert.Equal(t, want, h.originRequests.Load())
			h.assertStored(t, false)
		})
	}
}

func TestCacheFillShutdown(t *testing.T) {
	bucket := s3clienttest.Start(t)
	for _, strategyName := range []string{"codeartifact", "generic"} {
		t.Run(strategyName, func(t *testing.T) {
			h := newCacheFillHarness(t, bucket, strategyName, "complete")
			h.disconnect(t, false)
			shuttingDown := make(chan struct{})
			h.server.Config.RegisterOnShutdown(func() { close(shuttingDown) })
			done := make(chan error, 1)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			go func() { done <- h.server.Config.Shutdown(ctx) }()
			waitCacheFill(t, shuttingDown)
			select {
			case err := <-done:
				t.Fatalf("shutdown returned before cache commit: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			h.release()
			assert.NoError(t, <-done)
			waitCacheFill(t, h.finished)
			h.assertStored(t, false)
		})
	}
}

func TestCacheFillLateMiss(t *testing.T) {
	bucket := s3clienttest.Start(t)
	h := newCacheFillHarness(t, bucket, "codeartifact", "complete")
	h.disconnect(t, false)
	h.pauseMiss.Store(true)
	result := make(chan string, 1)
	go func() {
		resp, err := h.server.Client().Get(h.server.URL + h.path)
		if err != nil {
			result <- err.Error()
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			result <- err.Error()
			return
		}
		result <- string(body)
	}()
	waitCacheFill(t, h.missed)
	h.release()
	waitCacheFill(t, h.finished)
	h.resumeMiss()
	select {
	case body := <-result:
		assert.Equal(t, h.body, body)
	case <-time.After(5 * time.Second):
		t.Fatal("late request did not finish")
	}
	assert.Equal(t, int32(1), h.originRequests.Load())
	h.assertStored(t, false)
}

func TestUncacheableWaitersStayParallel(t *testing.T) {
	const callers = 8
	var requests atomic.Int32
	first := make(chan struct{})
	followers := make(chan struct{}, callers)
	releaseFirst := make(chan struct{})
	releaseFollowers := make(chan struct{})
	finishFirst := sync.OnceFunc(func() { close(releaseFirst) })
	finishFollowers := sync.OnceFunc(func() { close(releaseFollowers) })
	mux, origin, _, _, _ := newTestCachingCodeArtifact(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			close(first)
			<-releaseFirst
		} else {
			followers <- struct{}{}
			<-releaseFollowers
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, testCodeArtifactBody)
	}))
	entered := make(chan struct{}, callers)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(finishFirst)
	t.Cleanup(finishFollowers)
	results := make(chan string, callers)
	download := func() {
		resp, err := server.Client().Get(server.URL + codeArtifactPath(origin, "/future-format/repository/opaque/download"))
		if err != nil {
			results <- err.Error()
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			results <- err.Error()
			return
		}
		results <- string(body)
	}
	go download()
	waitCacheFill(t, first)
	for range callers - 1 {
		go download()
	}
	for range callers {
		waitCacheFill(t, entered)
	}
	finishFirst()
	for range callers - 1 {
		waitCacheFill(t, followers)
	}
	finishFollowers()
	for range callers {
		select {
		case body := <-results:
			assert.Equal(t, testCodeArtifactBody, body)
		case <-time.After(5 * time.Second):
			t.Fatal("uncacheable download did not finish")
		}
	}
	assert.Equal(t, int32(callers), requests.Load())
}
