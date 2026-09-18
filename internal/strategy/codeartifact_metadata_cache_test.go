package strategy //nolint:testpackage // Exercise the cache with real HTTP origins and injected service credentials.

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
)

func newMetadataCacheProxy(t *testing.T, origin http.Handler, config MetadataCacheConfig) (*http.ServeMux, *httptest.Server, *CodeArtifact) {
	t.Helper()
	server := httptest.NewServer(origin)
	t.Cleanup(server.Close)
	tokens := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	cfg := testCodeArtifactConfig(server.URL)
	cfg.MetadataCache = &config
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, cfg, mux, tokens.tokenManager(time.Now), cache.NoOpCache(), true)
	assert.NoError(t, err)
	return mux, server, strategy
}

func metadataCacheTestConfig() MetadataCacheConfig {
	return MetadataCacheConfig{Repositories: []string{"frontend"}, Formats: []string{"npm"}, TTL: 30 * time.Second, MaxBytes: 1 << 20, MaxConcurrent: 2}
}

func TestMetadataCacheVariants(t *testing.T) {
	var calls atomic.Int32
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Vary", "Accept")
		_, _ = fmt.Fprintf(w, `{"name":%q,"tarball":%q}`, r.Header.Get("Accept"), "http://"+r.Host+"/npm/frontend/react/-/react.tgz")
	}), metadataCacheTestConfig())
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

func TestMetadataCacheRefreshAndBypass(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusOK)
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = fmt.Fprintf(w, `{"version":%d}`, calls.Add(1))
	}), metadataCacheTestConfig())
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

func TestMetadataCacheOriginPolicy(t *testing.T) {
	for _, headers := range []http.Header{
		{"Cache-Control": {"no-store"}}, {"Cache-Control": {"no-cache"}}, {"Cache-Control": {"private"}},
		{"Cache-Control": {"max-age=0"}}, {"Cache-Control": {"max-age=1"}, "Age": {"2"}},
		{"Set-Cookie": {"a=b"}}, {"Vary": {"X-Custom"}}, {"Vary": {"*"}}, {"Expires": {"invalid"}},
	} {
		t.Run(fmt.Sprint(headers), func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				maps.Copy(w.Header(), headers)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"version":%d}`, calls.Add(1))
			}), metadataCacheTestConfig())
			for range 2 {
				mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestMetadataCacheCoalescingCancellationAndCapacity(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	config := metadataCacheTestConfig()
	config.MaxConcurrent = 1
	mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	recorded := recordMetadataMetrics(strategy)
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
			waiter := &metadataWaitContext{Context: t.Context(), joined: joined}
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
	assert.Equal(t, map[codeArtifactCacheEvent]int{codeArtifactCacheMiss: 1, codeArtifactCacheCoalesced: 8, codeArtifactCacheCapacityRejected: 1, codeArtifactCacheStored: 1}, recorded.events()) //nolint:exhaustive // Assert only events emitted by this scenario.
}

func TestMetadataCacheByteBudget(t *testing.T) {
	var calls atomic.Int32
	config := metadataCacheTestConfig()
	mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":%q}`, strings.Repeat("x", 600<<10))
	}), config)
	recorded := recordMetadataMetrics(strategy)
	for _, name := range []string{"first", "second", "first", "first"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/"+name), nil))
		assert.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, int32(3), calls.Load())
	assert.Equal(t, map[codeArtifactCacheEvent]int{codeArtifactCacheMiss: 3, codeArtifactCacheStored: 3, codeArtifactCacheHit: 1, codeArtifactCacheEvicted: 2}, recorded.events()) //nolint:exhaustive // Assert only events emitted by this scenario.
}

func TestMetadataExpiryBudget(t *testing.T) {
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
			response := &metadataResponse{headers: tt.headers, stored: now}
			assert.Equal(t, now.Add(-3*time.Second).Add(tt.duration), metadataExpiry(response, now.Add(-3*time.Second), 30*time.Second))
		})
	}
}

func TestMetadataExpiryRejectsOverageOrigin(t *testing.T) {
	now := time.Now()
	response := &metadataResponse{headers: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"100"}}, stored: now}
	assert.True(t, metadataExpiry(response, now, 30*time.Second).IsZero())
}

func TestMetadataCacheRejectsOversizedAndFailedResponses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		body   string
		status int
	}{
		{"above retention budget", `{"data":"` + strings.Repeat("x", 1100<<10) + `"}`, http.StatusOK},
		{"malformed JSON", `{"broken":`, http.StatusBadGateway},
		{"multiple documents", `{"one":1}{"two":2}`, http.StatusBadGateway},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tt.body)
			}), metadataCacheTestConfig())
			for range 2 {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
				assert.Equal(t, tt.status, w.Code)
				if tt.status == http.StatusOK {
					assert.Equal(t, tt.body, w.Body.String())
				}
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestMetadataCacheConfigValidation(t *testing.T) {
	for _, change := range []func(*MetadataCacheConfig){
		func(c *MetadataCacheConfig) { c.TTL = 0 }, func(c *MetadataCacheConfig) { c.TTL = 6 * time.Minute },
		func(c *MetadataCacheConfig) { c.MaxBytes = 0 }, func(c *MetadataCacheConfig) { c.MaxBytes = 2 << 30 },
		func(c *MetadataCacheConfig) { c.MaxConcurrent = 33 }, func(c *MetadataCacheConfig) { c.Repositories = nil },
		func(c *MetadataCacheConfig) { c.Repositories = []string{"frontend/@scope"} },
		func(c *MetadataCacheConfig) { c.Repositories = []string{"*", "frontend"} },
		func(c *MetadataCacheConfig) { c.Formats = nil },
		func(c *MetadataCacheConfig) { c.Formats = []string{"*"} },
		func(c *MetadataCacheConfig) { c.Formats = []string{"nuget"} },
	} {
		config := metadataCacheTestConfig()
		change(&config)
		cfg := testCodeArtifactConfig("https://codeartifact.example.com")
		cfg.MetadataCache = &config
		_, _, err := validateCodeArtifactConfig(cfg, false)
		assert.Error(t, err)
	}
}

func TestMetadataCacheInvalidatesAllVariantsOnRemoval(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, `{"name":"package"}`)
	}), metadataCacheTestConfig())
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

func TestMetadataRemovalInvalidatesConcurrentFill(t *testing.T) {
	for _, bypass := range []bool{false, true} {
		t.Run(fmt.Sprintf("bypass=%t", bypass), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var fullCalls atomic.Int32
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			}), metadataCacheTestConfig())
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

func TestMetadataBypassInvalidatesAuthoritativeFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone, http.StatusUnavailableForLegalReasons, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var removed atomic.Bool
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if removed.Load() {
					w.WriteHeader(status)
				}
				_, _ = io.WriteString(w, `{"name":"package"}`)
			}), metadataCacheTestConfig())
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

func TestMetadataPrivateLinkRepositoryIsolation(t *testing.T) {
	for _, host := range []string{"vpce-test.codeartifact.repositories.us-east-1.vpce.amazonaws.com", "vpce-test.codeartifact.repositories.cn-north-1.vpce.amazonaws.com.cn", "packages.example.com"} {
		t.Run(host, func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"path":%q}`, r.URL.EscapedPath())
			}), metadataCacheTestConfig())
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

type metadataWaitContext struct {
	context.Context
	joined chan<- struct{}
	once   sync.Once
}

func (c *metadataWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { c.joined <- struct{}{} })
	return c.Context.Done()
}

func TestMetadataCacheExpiryDoesNotSlide(t *testing.T) {
	var calls atomic.Int32
	var clock atomic.Int64
	start := time.Date(2026, 9, 18, 20, 0, 0, 0, time.UTC)
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	config := metadataCacheTestConfig()
	mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"version":%d}`, calls.Add(1))
	}), config)
	strategy.metadata.now = now
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

func TestMetadataCoalescesUnretainedResponses(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	for _, tt := range []struct {
		name    string
		status  int
		headers http.Header
		padding int
		expire  bool
		shared  bool
	}{
		{name: "origin error", status: http.StatusBadGateway, shared: true},
		{name: "not found", status: http.StatusNotFound, shared: true},
		{name: "above retention budget", status: http.StatusOK, padding: 1100 << 10, shared: true},
		{name: "expires during fetch", status: http.StatusOK, expire: true, shared: true},
		{name: "private", status: http.StatusOK, headers: http.Header{"Cache-Control": {"private"}}},
		{name: "private error", status: http.StatusBadGateway, headers: http.Header{"Cache-Control": {"private"}}},
		{name: "no store", status: http.StatusOK, headers: http.Header{"Cache-Control": {"no-store"}}},
		{name: "cookie", status: http.StatusOK, headers: http.Header{"Set-Cookie": {"session=value"}}},
		{name: "unsupported vary", status: http.StatusOK, headers: http.Header{"Vary": {"X-Custom"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var calls atomic.Int32
			var clock atomic.Int64
			clock.Store(time.Now().UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()) }
			mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if n == 1 {
					close(entered)
				}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				maps.Copy(w.Header(), tt.headers)
				w.Header().Set("Date", now().UTC().Format(http.TimeFormat))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = fmt.Fprintf(w, `{"call":%d,"padding":%q}`, n, strings.Repeat("x", tt.padding))
			}), metadataCacheTestConfig())
			strategy.metadata.now = now
			done := make(chan *httptest.ResponseRecorder, 3)
			request := func(ctx context.Context) {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil).WithContext(ctx))
				done <- w
			}
			go request(t.Context())
			<-entered
			joined := make(chan struct{}, 2)
			for range 2 {
				go request(&metadataWaitContext{Context: t.Context(), joined: joined})
			}
			for range 2 {
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Fatal("follower did not join")
				}
			}
			if tt.expire {
				clock.Add(int64(time.Minute))
			}
			close(release)
			bodies := map[string]bool{}
			for range 3 {
				select {
				case w := <-done:
					assert.Equal(t, tt.status, w.Code)
					bodies[w.Body.String()] = true
				case <-time.After(5 * time.Second):
					t.Fatal("waiter did not complete")
				}
			}
			want := int32(3)
			if tt.shared {
				want = 1
			}
			assert.Equal(t, want, calls.Load())
			assert.Equal(t, int(want), len(bodies))
			request(t.Context())
			assert.Equal(t, tt.status, (<-done).Code)
			assert.Equal(t, want+1, calls.Load(), "completed response must not be retained")
			files, err := os.ReadDir(directory)
			assert.NoError(t, err)
			assert.Equal(t, 0, len(files))
		})
	}
}

func TestMetadataWaitDeadlineSpansUnshareableFills(t *testing.T) {
	mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), metadataCacheTestConfig())
	_, err := strategy.authorizationToken(t.Context())
	assert.NoError(t, err)
	synctest.Test(t, func(t *testing.T) {
		strategy.metadata.ctx = t.Context()
		var calls atomic.Int32
		strategy.client.Transport = codeArtifactRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			select {
			case <-time.After(40 * time.Second):
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"private"}}, Body: io.NopCloser(strings.NewReader(`{"name":"react"}`)), Request: r}, nil
		})
		started := time.Now()
		done := make(chan *httptest.ResponseRecorder, 3)
		for range 3 {
			go func() {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
				done <- w
			}()
		}
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		counts := map[int]int{}
		for range 3 {
			counts[(<-done).Code]++
		}
		assert.Equal(t, map[int]int{http.StatusOK: 1, http.StatusGatewayTimeout: 2}, counts)
		assert.Equal(t, time.Minute, time.Since(started))
		assert.Equal(t, int32(2), calls.Load())
	})
}

func TestMetadataCacheDeliversExpandedMetadata(t *testing.T) {
	const expandedCharacters = (64<<20)/6 + 1
	var calls atomic.Int32
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"data":"`+strings.Repeat("<", expandedCharacters)+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":"next"}`)
	}), metadataCacheTestConfig())
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, w.Body.Len() > 64<<20)
	var metadata struct {
		Data string `json:"data"`
	}
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&metadata))
	assert.Equal(t, strings.Repeat("<", expandedCharacters), metadata.Data)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/npm/frontend/react"), nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"data":"next"}`, w.Body.String())
	assert.Equal(t, int32(2), calls.Load())
}

type recordingMetadataMetrics struct {
	codeArtifactMetricRecorder
	mu          sync.Mutex
	cacheEvents map[codeArtifactCacheEvent]int
}

func recordMetadataMetrics(strategy *CodeArtifact) *recordingMetadataMetrics {
	recorded := &recordingMetadataMetrics{codeArtifactMetricRecorder: strategy.metric, cacheEvents: map[codeArtifactCacheEvent]int{}}
	strategy.metric = recorded
	return recorded
}

func (m *recordingMetadataMetrics) recordCache(_ context.Context, event codeArtifactCacheEvent, tier codeArtifactCacheTier) {
	if tier != codeArtifactCacheTierMetadata {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheEvents[event]++
}

func (m *recordingMetadataMetrics) events() map[codeArtifactCacheEvent]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.cacheEvents)
}
