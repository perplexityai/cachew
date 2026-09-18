package strategy //nolint:testpackage // Exercise the cache with real HTTP origins and injected service credentials.

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
)

func newNPMCacheProxy(t *testing.T, origin http.Handler, config NPMMetadataCacheConfig) (*http.ServeMux, *httptest.Server, *CodeArtifact) {
	t.Helper()
	server := httptest.NewServer(origin)
	t.Cleanup(server.Close)
	tokens := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	cfg := testCodeArtifactConfig(server.URL)
	cfg.NPMMetadataCache = &config
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, cfg, mux, tokens.tokenManager(time.Now), cache.NoOpCache(), true)
	assert.NoError(t, err)
	return mux, server, strategy
}

func npmCacheTestConfig() NPMMetadataCacheConfig {
	return NPMMetadataCacheConfig{Repositories: []string{"frontend"}, TTL: 30 * time.Second, MaxBytes: 1 << 20, MaxConcurrent: 2}
}

func TestNPMMetadataCacheVariants(t *testing.T) {
	var calls atomic.Int32
	mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Vary", "Accept")
		_, _ = fmt.Fprintf(w, `{"name":%q,"tarball":%q}`, r.Header.Get("Accept"), "http://"+r.Host+"/npm/frontend/react/-/react.tgz")
	}), npmCacheTestConfig())
	for _, path := range []string{"react", "@sanity%2Fvision", "@sanity/vision"} {
		for _, accept := range []string{"application/json", "application/vnd.npm.install-v1+json"} {
			for _, encoding := range []string{"identity", "gzip"} {
				before := calls.Load()
				for range 2 {
					req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/"+path), nil)
					req.Header.Set("Accept", accept)
					req.Header.Set("Accept-Encoding", encoding)
					w := httptest.NewRecorder()
					mux.ServeHTTP(w, req)
					assert.Equal(t, http.StatusOK, w.Code)
					var body io.Reader = w.Body
					if encoding == "gzip" {
						reader, err := gzip.NewReader(w.Body)
						assert.NoError(t, err)
						defer reader.Close()
						body = reader
					}
					data, err := io.ReadAll(body)
					assert.NoError(t, err)
					assert.Contains(t, string(data), `"name":"`+accept+`"`)
					assert.Contains(t, string(data), "https://cachew.example.com/"+origin.Listener.Addr().String()+"/npm/frontend/react/-/react.tgz")
				}
				assert.Equal(t, before+1, calls.Load())
			}
		}
	}
}

func TestNPMMetadataCacheRefreshAndBypass(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusOK)
	mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = fmt.Fprintf(w, `{"version":%d}`, calls.Add(1))
	}), npmCacheTestConfig())
	request := func(path, directive string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, path), nil)
		if directive != "" {
			req.Header.Set("Cache-Control", directive)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	const path = "/npm/frontend/react"
	assert.Equal(t, `{"version":1}`, request(path, "").Body.String())
	assert.Equal(t, `{"version":1}`, request(path, "").Body.String())
	assert.Equal(t, `{"version":2}`, request(path, "no-cache").Body.String())
	assert.Equal(t, `{"version":2}`, request(path, "").Body.String())
	assert.Equal(t, `{"version":3}`, request(path, "no-store").Body.String())
	assert.Equal(t, `{"version":2}`, request(path, "").Body.String())
	assert.Equal(t, `{"version":4}`, request(path, "max-age=0").Body.String())
	status.Store(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, request(path, "no-cache").Code)
	assert.Equal(t, http.StatusNotFound, request(path, "").Code)
	status.Store(http.StatusOK)
	for _, path := range []string{"/npm/other/react", "/npm/frontend/react/19.0.0", "/npm/frontend/react?query=yes"} {
		before := calls.Load()
		request(path, "")
		request(path, "")
		assert.Equal(t, before+2, calls.Load())
	}
}

func TestNPMMetadataCacheOriginPolicy(t *testing.T) {
	for _, headers := range []http.Header{
		{"Cache-Control": {"no-store"}}, {"Cache-Control": {"no-cache"}}, {"Cache-Control": {"private"}},
		{"Cache-Control": {"max-age=0"}}, {"Cache-Control": {"max-age=1"}, "Age": {"2"}},
		{"Set-Cookie": {"a=b"}}, {"Vary": {"X-Custom"}}, {"Vary": {"*"}}, {"Expires": {"invalid"}},
	} {
		t.Run(fmt.Sprint(headers), func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				maps.Copy(w.Header(), headers)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"version":%d}`, calls.Add(1))
			}), npmCacheTestConfig())
			for range 2 {
				mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestNPMMetadataCacheCoalescingCancellationAndCapacity(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	config := npmCacheTestConfig()
	config.MaxConcurrent = 1
	mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"react"}`)
	}), config)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil).WithContext(ctx)
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-entered
	cancel()
	<-done
	busy := httptest.NewRecorder()
	mux.ServeHTTP(busy, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/other"), nil))
	assert.Equal(t, http.StatusServiceUnavailable, busy.Code)
	joined := make(chan struct{}, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			w := httptest.NewRecorder()
			waiter := &npmMetadataWaitContext{Context: t.Context(), joined: joined}
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil).WithContext(waiter))
			assert.Equal(t, `{"name":"react"}`, w.Body.String())
		})
	}
	for range 8 {
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Fatal("followers did not join the active fill")
		}
	}
	close(release)
	group.Wait()
	assert.Equal(t, int32(1), calls.Load())
}

func TestNPMMetadataCacheByteBudget(t *testing.T) {
	var calls atomic.Int32
	config := npmCacheTestConfig()
	mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":%q}`, strings.Repeat("x", 600<<10))
	}), config)
	for _, name := range []string{"first", "second", "first", "first"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/"+name), nil))
		assert.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, int32(3), calls.Load())
}

func TestNPMMetadataExpiryBudget(t *testing.T) {
	now := time.Date(2026, 9, 18, 20, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name     string
		headers  http.Header
		duration time.Duration
	}{
		{"missing freshness", http.Header{}, 30 * time.Second},
		{"origin age", http.Header{"Age": {"10"}}, 20 * time.Second},
		{"origin date", http.Header{"Date": {now.Add(-10 * time.Second).Format(http.TimeFormat)}}, 20 * time.Second},
		{"origin shorter", http.Header{"Cache-Control": {"max-age=5"}}, 5 * time.Second},
		{"origin longer", http.Header{"Cache-Control": {"max-age=600"}}, 30 * time.Second},
		{"origin longer with age", http.Header{"Cache-Control": {"max-age=600"}, "Age": {"10"}}, 20 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := &npmMetadataResponse{headers: tt.headers, stored: now}
			assert.Equal(t, now.Add(-3*time.Second).Add(tt.duration), npmMetadataExpiry(response, now.Add(-3*time.Second), 30*time.Second))
		})
	}
}

func TestNPMMetadataExpiryRejectsOverageOrigin(t *testing.T) {
	now := time.Now()
	response := &npmMetadataResponse{headers: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"100"}}, stored: now}
	assert.True(t, npmMetadataExpiry(response, now, 30*time.Second).IsZero())
}

func TestNPMMetadataCacheRejectsOversizedAndFailedResponses(t *testing.T) {
	for _, body := range []string{`{"data":"` + strings.Repeat("x", 1100<<10) + `"}`, `{"broken":`, `{"one":1}{"two":2}`} {
		var calls atomic.Int32
		mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}), npmCacheTestConfig())
		for range 2 {
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
		}
		assert.Equal(t, int32(2), calls.Load())
	}
}

func TestNPMMetadataCacheConfigValidation(t *testing.T) {
	for _, change := range []func(*NPMMetadataCacheConfig){
		func(c *NPMMetadataCacheConfig) { c.TTL = 0 }, func(c *NPMMetadataCacheConfig) { c.TTL = 6 * time.Minute },
		func(c *NPMMetadataCacheConfig) { c.MaxBytes = 0 }, func(c *NPMMetadataCacheConfig) { c.MaxBytes = 2 << 30 },
		func(c *NPMMetadataCacheConfig) { c.MaxConcurrent = 33 }, func(c *NPMMetadataCacheConfig) { c.Repositories = nil },
		func(c *NPMMetadataCacheConfig) { c.Repositories = []string{"frontend/@scope"} },
	} {
		config := npmCacheTestConfig()
		change(&config)
		cfg := testCodeArtifactConfig("https://codeartifact.example.com")
		cfg.NPMMetadataCache = &config
		_, _, err := validateCodeArtifactConfig(cfg, false)
		assert.Error(t, err)
	}
}

func TestNPMMetadataCacheInvalidatesAllVariantsOnRemoval(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, `{"name":"package"}`)
	}), npmCacheTestConfig())
	request := func(accept, encoding, path, directive string) int {
		req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/"+path), nil)
		req.Header.Set("Accept", accept)
		req.Header.Set("Accept-Encoding", encoding)
		req.Header.Set("Cache-Control", directive)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	assert.Equal(t, http.StatusOK, request("full", "identity", "@scope/package", ""))
	assert.Equal(t, http.StatusOK, request("brief", "gzip", "@scope%2Fpackage", ""))
	status.Store(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, request("brief", "gzip", "@scope%2Fpackage", "no-cache"))
	assert.Equal(t, http.StatusNotFound, request("full", "identity", "@scope/package", ""))
}

func TestNPMMetadataRemovalInvalidatesConcurrentFill(t *testing.T) {
	for _, bypass := range []bool{false, true} {
		t.Run(fmt.Sprintf("bypass=%t", bypass), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var fullCalls atomic.Int32
			mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Accept") == "full" && fullCalls.Add(1) == 1 {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
				_, _ = io.WriteString(w, `{"name":"package"}`)
			}), npmCacheTestConfig())
			request := func(accept string) int {
				req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil)
				req.Header.Set("Accept", accept)
				if bypass && accept == "brief" {
					req.Header.Set("If-None-Match", `"old"`)
					req.Header.Set("Cache-Control", "no-cache")
				}
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)
				return w.Code
			}
			done := make(chan int, 1)
			go func() { done <- request("full") }()
			<-entered
			assert.Equal(t, http.StatusNotFound, request("brief"))
			close(release)
			assert.Equal(t, http.StatusOK, <-done)
			assert.Equal(t, http.StatusNotFound, request("full"))
			assert.Equal(t, int32(2), fullCalls.Load())
		})
	}
}

func TestNPMMetadataBypassInvalidatesAuthoritativeFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var removed atomic.Bool
			mux, origin, _ := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if removed.Load() {
					w.WriteHeader(status)
				}
				_, _ = io.WriteString(w, `{"name":"package"}`)
			}), npmCacheTestConfig())
			request := func(accept string, refresh bool) int {
				req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil)
				req.Header.Set("Accept", accept)
				if refresh {
					req.Header.Set("Cache-Control", "no-cache")
					req.Header.Set("If-None-Match", `"old"`)
				}
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)
				return w.Code
			}
			assert.Equal(t, http.StatusOK, request("full", false))
			assert.Equal(t, http.StatusOK, request("brief", false))
			removed.Store(true)
			assert.Equal(t, status, request("full", true))
			assert.Equal(t, status, request("full", false))
			if status != http.StatusBadGateway {
				assert.Equal(t, status, request("brief", false))
			} else {
				assert.Equal(t, http.StatusOK, request("brief", false))
			}
		})
	}
}

func TestNPMMetadataPrivateLinkRepositoryIsolation(t *testing.T) {
	for _, host := range []string{"vpce-test.codeartifact.repositories.us-east-1.vpce.amazonaws.com", "vpce-test.codeartifact.repositories.cn-north-1.vpce.amazonaws.com.cn", "packages.example.com"} {
		t.Run(host, func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, strategy := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"path":%q}`, r.URL.EscapedPath())
			}), npmCacheTestConfig())
			strategy.target.Host = host
			transport := strategy.client.Transport
			strategy.client.Transport = codeArtifactRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
				req := r.Clone(r.Context())
				req.URL.Host = origin.Listener.Addr().String()
				return transport.RoundTrip(req)
			})
			for _, path := range []string{
				"/npm/d/domain-a-123456789012/frontend/react", "/npm/d/domain-b-123456789012/frontend/react",
				"/npm/d/domain-a-123456789012/frontend/@sanity%2Fvision", "/npm/d/domain-a-123456789012/other/react",
				"/npm/d/domain%2Fa/frontend/react",
			} {
				before := calls.Load()
				for range 2 {
					w := httptest.NewRecorder()
					mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, path), nil))
					assert.Equal(t, http.StatusOK, w.Code)
					assert.Equal(t, fmt.Sprintf(`{"path":%q}`, path), w.Body.String())
				}
				want := int32(1)
				if host == "packages.example.com" || strings.Contains(path, "/other/") || strings.Contains(path, "domain%2F") {
					want = 2
				}
				assert.Equal(t, before+want, calls.Load())
			}
		})
	}
}

type npmMetadataWaitContext struct {
	context.Context
	joined chan<- struct{}
	once   sync.Once
}

func (c *npmMetadataWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { c.joined <- struct{}{} })
	return c.Context.Done()
}

func TestNPMMetadataCacheExpiryDoesNotSlide(t *testing.T) {
	var calls atomic.Int32
	var clock atomic.Int64
	start := time.Date(2026, 9, 18, 20, 0, 0, 0, time.UTC)
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	config := npmCacheTestConfig()
	mux, origin, strategy := newNPMCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"version":%d}`, calls.Add(1))
	}), config)
	strategy.npmMetadata.now = now
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
		return w
	}
	assert.Equal(t, `{"version":1}`, request().Body.String())
	clock.Store(start.Add(config.TTL - time.Second).UnixNano())
	warm := request()
	assert.Equal(t, `{"version":1}`, warm.Body.String())
	assert.Equal(t, "29", warm.Header().Get("Age"))
	clock.Store(start.Add(config.TTL).UnixNano())
	assert.Equal(t, `{"version":2}`, request().Body.String())
	assert.Equal(t, int32(2), calls.Load())
}
