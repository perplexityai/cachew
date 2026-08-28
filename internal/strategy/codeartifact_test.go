package strategy //nolint:testpackage // White-box coverage is required for token and transport injection.

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
)

const (
	testCodeArtifactDomain         = "example"
	testCodeArtifactDomainOwner    = "123456789012"
	testCodeArtifactRegion         = "us-east-1"
	testCodeArtifactRoleARN        = "arn:aws:iam::123456789012:role/cachew-reader"
	testCodeArtifactETag           = `"asset-v1"`
	testCodeArtifactBody           = "immutable payload"
	testCodeArtifactModified       = "Wed, 21 Oct 2015 07:28:00 GMT"
	testCodeArtifactBeforeModified = "Wed, 21 Oct 2015 07:27:59 GMT"
	testCodeArtifactFutureModified = "Wed, 21 Oct 2030 07:28:00 GMT"
)

type tokenResponse struct {
	token     string
	expiresAt time.Time
	status    int
}

type localTokenServer struct {
	server *httptest.Server

	mu        sync.Mutex
	responses []tokenResponse
	requests  int
	method    string
	path      string
	query     url.Values
}

func newLocalTokenServer(t *testing.T, responses ...tokenResponse) *localTokenServer {
	t.Helper()
	s := &localTokenServer{responses: responses}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		index := s.requests
		s.requests++
		s.method = r.Method
		s.path = r.URL.Path
		s.query = r.URL.Query()
		if index >= len(s.responses) {
			index = len(s.responses) - 1
		}
		response := s.responses[index]
		s.mu.Unlock()

		if response.status != 0 {
			http.Error(w, http.StatusText(response.status), response.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			w,
			`{"authorizationToken":%q,"expiration":%f}`,
			response.token,
			float64(response.expiresAt.Unix()),
		)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *localTokenServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *localTokenServer) tokenManager(now func() time.Time) *codeArtifactTokenManager {
	awsConfig := aws.Config{
		Credentials: credentials.NewStaticCredentialsProvider("access-key", "secret-key", "session-token"),
		HTTPClient:  s.server.Client(),
		Region:      testCodeArtifactRegion,
	}
	client := awscodeartifact.NewFromConfig(awsConfig, func(options *awscodeartifact.Options) {
		options.BaseEndpoint = aws.String(s.server.URL)
	})
	return newCodeArtifactTokenManagerWithClient(testCodeArtifactConfig("https://codeartifact.example.com"), client, now)
}

func testCodeArtifactConfig(target string) CodeArtifactConfig {
	return CodeArtifactConfig{
		Target:      target,
		Domain:      testCodeArtifactDomain,
		DomainOwner: testCodeArtifactDomainOwner,
		Region:      testCodeArtifactRegion,
		RoleARN:     testCodeArtifactRoleARN,
	}
}

func newTestCodeArtifact(
	t *testing.T,
	origin http.Handler,
	responses ...tokenResponse,
) (*http.ServeMux, *httptest.Server, *localTokenServer, context.Context) {
	t.Helper()
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, responses...)

	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	mux := http.NewServeMux()
	_, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), cache.NoOpCache(), true)
	assert.NoError(t, err)
	return mux, originServer, tokenServer, ctx
}

func newTestCachingCodeArtifact(
	t *testing.T,
	origin http.Handler,
) (*http.ServeMux, *httptest.Server, *localTokenServer, *CodeArtifact, context.Context) {
	t.Helper()
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})

	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), memory, true)
	assert.NoError(t, err)
	return mux, originServer, tokenServer, strategy, ctx
}

func codeArtifactPath(origin *httptest.Server, suffix string) string {
	return "/" + origin.Listener.Addr().String() + suffix
}

func decodeBasicPassword(header string) (string, bool) {
	const prefix = "Basic "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", false
	}
	username, password, ok := string(decoded), "", false
	if colon := len(codeArtifactUsername); len(username) > colon && username[:colon] == codeArtifactUsername && username[colon] == ':' {
		password, ok = username[colon+1:], true
	}
	return password, ok
}

type codeArtifactRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f codeArtifactRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestCodeArtifactSanitizesOriginTransportErrors(t *testing.T) {
	target, err := url.Parse("https://codeartifact.example.com")
	assert.NoError(t, err)
	strategy := &CodeArtifact{
		target: target,
		prefix: "/codeartifact.example.com",
		client: &http.Client{Transport: codeArtifactRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "credential=must-not-be-logged", r.URL.RawQuery)
			return nil, errors.Errorf("transport failed for %s", r.URL)
		})},
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"/codeartifact.example.com/maven/repository/package?credential=must-not-be-logged",
		nil,
	)

	_, err = strategy.do(request, "token")
	assert.EqualError(t, err, "request CodeArtifact origin")
}

func TestCodeArtifactCachesReviewedImmutableAssets(t *testing.T) {
	for _, suffix := range []string{
		"/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3-darwin-arm64.tar.gz",
		"/generic/repository/devx/tool/1.2.3/darwin/arm64/tool.tar.gz",
		"/generic/repository/devx/tool/v1.2.3/tool.tar.gz",
	} {
		t.Run(suffix, func(t *testing.T) {
			var requests atomic.Int32
			origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("ETag", testCodeArtifactETag)
				_, _ = w.Write([]byte(testCodeArtifactBody))
			})
			mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
			requestURL := codeArtifactPath(originServer, suffix)

			for range 2 {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx))
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, testCodeArtifactBody, w.Body.String())
				assert.Equal(t, testCodeArtifactETag, w.Header().Get("ETag"))
			}

			assert.Equal(t, int32(1), requests.Load(), "the second request should hit Cachew")
			assert.Equal(t, 1, tokenServer.requestCount(), "a cache hit should not request origin authorization")
		})
	}
}

func TestCodeArtifactPreservesValidatorsAcrossCacheHits(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", testCodeArtifactETag)
		w.Header().Set("Last-Modified", testCodeArtifactModified)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	prime := httptest.NewRecorder()
	mux.ServeHTTP(prime, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
	assert.Equal(t, http.StatusOK, prime.Code)
	assert.Equal(t, testCodeArtifactETag, prime.Header().Get("ETag"))
	assert.Equal(t, testCodeArtifactModified, prime.Header().Get("Last-Modified"))

	tests := []struct {
		name       string
		headers    http.Header
		statusCode int
		body       string
	}{
		{name: "matching If-None-Match", headers: http.Header{"If-None-Match": {testCodeArtifactETag}}, statusCode: http.StatusNotModified},
		{name: "weak If-None-Match", headers: http.Header{"If-None-Match": {`W/"asset-v1"`}}, statusCode: http.StatusNotModified},
		{name: "matching If-Match", headers: http.Header{"If-Match": {testCodeArtifactETag}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "matching If-Match list", headers: http.Header{"If-Match": {`"asset-v0", "asset-v1"`}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "failed If-Match", headers: http.Header{"If-Match": {`"asset-v0"`}}, statusCode: http.StatusPreconditionFailed},
		{name: "weak If-Match fails", headers: http.Header{"If-Match": {`W/"asset-v1"`}}, statusCode: http.StatusPreconditionFailed},
		{name: "not modified since", headers: http.Header{"If-Modified-Since": {testCodeArtifactModified}}, statusCode: http.StatusNotModified},
		{name: "modified since", headers: http.Header{"If-Modified-Since": {testCodeArtifactBeforeModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "failed unmodified since", headers: http.Header{"If-Unmodified-Since": {testCodeArtifactBeforeModified}}, statusCode: http.StatusPreconditionFailed},
		{name: "unmodified since", headers: http.Header{"If-Unmodified-Since": {testCodeArtifactModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "If-Unmodified-Since precedence", headers: http.Header{"If-Unmodified-Since": {testCodeArtifactBeforeModified}, "If-None-Match": {testCodeArtifactETag}}, statusCode: http.StatusPreconditionFailed},
		{name: "If-None-Match precedence", headers: http.Header{"If-None-Match": {`"asset-v0"`}, "If-Modified-Since": {testCodeArtifactModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "If-Match precedence", headers: http.Header{"If-Match": {testCodeArtifactETag}, "If-Unmodified-Since": {testCodeArtifactBeforeModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "invalid date ignored", headers: http.Header{"If-Modified-Since": {"not-a-date"}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
			req.Header = test.headers
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.body, w.Body.String())
			if test.statusCode != http.StatusPreconditionFailed {
				assert.Equal(t, testCodeArtifactETag, w.Header().Get("ETag"))
				assert.Equal(t, testCodeArtifactModified, w.Header().Get("Last-Modified"))
			}
		})
	}

	assert.Equal(t, int32(1), requests.Load(), "validator requests should use the cached representation")
	assert.Equal(t, 1, tokenServer.requestCount(), "validator cache hits should not request origin authorization")
}

func TestCodeArtifactDoesNotCacheUnsupportedOriginETags(t *testing.T) {
	const weakETag = `W/"asset-v1"`
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", weakETag)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/generic/repository/devx/tool/1.2.3/tool.tar.gz")

	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, weakETag, w.Header().Get("ETag"))
		assert.Equal(t, testCodeArtifactBody, w.Body.String())
	}

	assert.Equal(t, int32(2), requests.Load(), "an origin validator Cachew cannot preserve must bypass cache")
}

func TestCodeArtifactDoesNotExposeGeneratedValidators(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	tests := []struct {
		name       string
		headers    http.Header
		statusCode int
		body       string
	}{
		{name: "cold response", statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "warm response", statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "date condition ignored", headers: http.Header{"If-Modified-Since": {testCodeArtifactFutureModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "wildcard If-None-Match", headers: http.Header{"If-None-Match": {"*"}}, statusCode: http.StatusNotModified},
		{name: "wildcard If-Match", headers: http.Header{"If-Match": {"*"}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
			req.Header = test.headers
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.body, w.Body.String())
			assert.Equal(t, "", w.Header().Get("ETag"))
			assert.Equal(t, "", w.Header().Get("Last-Modified"))
			assert.Equal(t, "", w.Header().Get(codeArtifactOriginValidatorsHeader))
		})
	}

	assert.Equal(t, int32(1), requests.Load(), "cache metadata must not leak as origin validators")
	assert.Equal(t, 1, tokenServer.requestCount())
}

func TestCodeArtifactDoesNotCacheRangesOrUnsuccessfulResponses(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Has("missing") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Range") != "" {
			w.Header().Set("Content-Range", "bytes 0-3/7")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte("part"))
			return
		}
		_, _ = w.Write([]byte("complete"))
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
		req.Header.Set("Range", "bytes=0-3")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusPartialContent, w.Code)
		assert.Equal(t, "part", w.Body.String())
	}
	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL+"?missing", nil).WithContext(ctx))
		assert.Equal(t, http.StatusNotFound, w.Code)
	}
	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "complete", w.Body.String())
	}

	assert.Equal(t, int32(5), requests.Load(), "only the final full response should populate cache")
}

func TestCodeArtifactDoesNotCacheIncompleteResponses(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		hijacker, ok := w.(http.Hijacker)
		assert.True(t, ok)
		conn, output, err := hijacker.Hijack()
		assert.NoError(t, err)
		defer conn.Close()
		_, _ = output.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort")
		assert.NoError(t, output.Flush())
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/generic/repository/devx/tool/1.2.3/tool.tar.gz")

	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "short", w.Body.String())
	}

	assert.Equal(t, int32(2), requests.Load(), "an interrupted body must abort the cache entry")
}

type recordingCodeArtifactMetrics struct {
	requests []codeArtifactCacheMode
	cache    []codeArtifactCacheEvent
	auth     []codeArtifactAuthEvent
}

func (m *recordingCodeArtifactMetrics) recordRequest(_ context.Context, mode codeArtifactCacheMode) {
	m.requests = append(m.requests, mode)
}

func (m *recordingCodeArtifactMetrics) recordCache(_ context.Context, event codeArtifactCacheEvent) {
	m.cache = append(m.cache, event)
}

func (m *recordingCodeArtifactMetrics) recordAuth(_ context.Context, event codeArtifactAuthEvent) {
	m.auth = append(m.auth, event)
}

func TestCodeArtifactMetricsExposeOnlyBoundedDecisions(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})
	mux, originServer, _, strategy, ctx := newTestCachingCodeArtifact(t, origin)
	recorded := &recordingCodeArtifactMetrics{}
	strategy.metric = recorded
	immutable := codeArtifactPath(originServer, "/maven/repository/com/perplexity/private-tool/1.2.3/private-tool-1.2.3.jar")
	mutable := codeArtifactPath(originServer, "/pypi/repository/simple/private-package/")

	for _, requestURL := range []string{immutable, immutable, mutable} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx))
	}

	assert.Equal(t, []codeArtifactCacheMode{codeArtifactCacheImmutable, codeArtifactCacheImmutable, codeArtifactCachePassthrough}, recorded.requests)
	assert.Equal(t, []codeArtifactCacheEvent{codeArtifactCacheMiss, codeArtifactCacheStored, codeArtifactCacheHit}, recorded.cache)
	assert.Equal(t, []codeArtifactAuthEvent{codeArtifactAuthRefresh, codeArtifactAuthReuse}, recorded.auth)
}

type countingCache struct {
	cache.Cache
	opens   atomic.Int32
	creates atomic.Int32
}

func (c *countingCache) Open(ctx context.Context, key cache.Key, opts ...cache.Option) (io.ReadCloser, http.Header, error) {
	c.opens.Add(1)
	return c.Cache.Open(ctx, key, opts...)
}

func (c *countingCache) Create(ctx context.Context, key cache.Key, headers http.Header, ttl time.Duration, opts ...cache.Option) (cache.Writer, error) {
	c.creates.Add(1)
	return c.Cache.Create(ctx, key, headers, ttl, opts...)
}

func TestCodeArtifactMutableAndUnknownPathsBypassCache(t *testing.T) {
	paths := []string{
		"/maven/repository/com/perplexity/tool/maven-metadata.xml",
		"/maven/repository/com/perplexity/tool/1.2-SNAPSHOT/tool-1.2-SNAPSHOT.jar",
		"/generic/repository/devx/tool/tool.tar.gz",
		"/generic/repository/devx/tool/latest/tool.tar.gz",
		"/generic/repository/devx/tool/nightly/tool.tar.gz",
		"/generic/repository/devx/tool/main/tool.tar.gz",
		"/generic/repository/devx/tool/1.2/tool.tar.gz",
		"/generic/repository/devx/tool/01.2.3/tool.tar.gz",
		"/generic/repository/devx/tool/1.2.3-nightly/tool.tar.gz",
		"/generic/repository/devx/tool/1.2.3+build.1/tool.tar.gz",
		"/npm/repository/package/-/package-1.2.3.tgz",
	}
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("current"))
	})
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	tracked := &countingCache{Cache: cache.NoOpCache()}
	mux := http.NewServeMux()
	_, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), tracked, true)
	assert.NoError(t, err)

	for _, suffix := range paths {
		for range 2 {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, suffix), nil).WithContext(ctx))
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "current", w.Body.String())
		}
	}

	assert.Equal(t, int32(2*len(paths)), requests.Load())
	assert.Equal(t, int32(0), tracked.opens.Load(), "pass-through must not read cache")
	assert.Equal(t, int32(0), tracked.creates.Load(), "pass-through must not write cache")
}

func TestCodeArtifactPassesThroughReadSemantics(t *testing.T) {
	type observedRequest struct {
		method         string
		escapedPath    string
		rawQuery       string
		authorization  string
		cookie         string
		packageAuth    string
		rangeHeader    string
		ifNoneMatch    string
		removedHeader  string
		acceptEncoding string
	}
	var mu sync.Mutex
	var observed []observedRequest
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observed = append(observed, observedRequest{
			method:         r.Method,
			escapedPath:    r.URL.EscapedPath(),
			rawQuery:       r.URL.RawQuery,
			authorization:  r.Header.Get("Authorization"),
			cookie:         r.Header.Get("Cookie"),
			packageAuth:    r.Header.Get("X-Package-Authorization"),
			rangeHeader:    r.Header.Get("Range"),
			ifNoneMatch:    r.Header.Get("If-None-Match"),
			removedHeader:  r.Header.Get("X-Remove"),
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		})
		mu.Unlock()

		w.Header().Set("ETag", `"asset-v1"`)
		w.Header().Set("Content-Range", "bytes 0-6/12")
		w.Header().Set("Connection", "X-Origin-Hop")
		w.Header().Set("X-Origin-Hop", "remove-me")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("payload"))
	})

	expiresAt := time.Now().Add(time.Hour)
	mux, originServer, tokenServer, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "service-token", expiresAt: expiresAt})
	requestURL := codeArtifactPath(originServer, "/maven/repository/pkg%2Fname/file.whl?version=1&download=true")

	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer client-token")
		req.Header.Set("Cookie", "session=client-secret")
		req.Header.Set("X-Package-Authorization", "client-package-token")
		req.Header.Set("Range", "bytes=0-6")
		req.Header.Set("If-None-Match", `"asset-v0"`)
		req.Header.Set("Connection", "X-Remove")
		req.Header.Set("X-Remove", "remove-me")
		if i == 0 {
			req.Header.Set("Accept-Encoding", "gzip")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusPartialContent, w.Code)
		assert.Equal(t, "payload", w.Body.String())
		assert.Equal(t, `"asset-v1"`, w.Header().Get("ETag"))
		assert.Equal(t, "bytes 0-6/12", w.Header().Get("Content-Range"))
		assert.Equal(t, "", w.Header().Get("X-Origin-Hop"))
	}

	mu.Lock()
	requests := append([]observedRequest(nil), observed...)
	mu.Unlock()
	assert.Equal(t, 2, len(requests), "pass-through responses must not be cached")
	assert.Equal(t, http.MethodGet, requests[0].method)
	assert.Equal(t, "/maven/repository/pkg%2Fname/file.whl", requests[0].escapedPath)
	assert.Equal(t, "version=1&download=true", requests[0].rawQuery)
	password, ok := decodeBasicPassword(requests[0].authorization)
	assert.True(t, ok)
	assert.Equal(t, "service-token", password)
	assert.Equal(t, "", requests[0].cookie)
	assert.Equal(t, "", requests[0].packageAuth)
	assert.Equal(t, "bytes=0-6", requests[0].rangeHeader)
	assert.Equal(t, `"asset-v0"`, requests[0].ifNoneMatch)
	assert.Equal(t, "", requests[0].removedHeader)
	assert.Equal(t, "gzip", requests[0].acceptEncoding)
	assert.Equal(t, "", requests[1].acceptEncoding)
	assert.Equal(t, 1, tokenServer.requestCount(), "a valid token should be reused")
	assert.Equal(t, http.MethodPost, tokenServer.method)
	assert.Equal(t, "/v1/authorization-token", tokenServer.path)
	assert.Equal(t, testCodeArtifactDomain, tokenServer.query.Get("domain"))
	assert.Equal(t, testCodeArtifactDomainOwner, tokenServer.query.Get("domain-owner"))
}

func TestCodeArtifactPreservesHEADWithoutBody(t *testing.T) {
	var method string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.Header().Set("Content-Length", "123")
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("must not reach client"))
	})
	mux, originServer, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})

	req := httptest.NewRequest(http.MethodHead, codeArtifactPath(originServer, "/npm/repository/package"), nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, http.MethodHead, method)
	assert.Equal(t, "", w.Body.String())
	assert.Equal(t, "123", w.Header().Get("Content-Length"))
	assert.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", w.Header().Get("Last-Modified"))
}

func TestCodeArtifactRefreshesRejectedTokenOnce(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		password, _ := decodeBasicPassword(r.Header.Get("Authorization"))
		if password == "stale-token" {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "fresh-token", password)
		_, _ = w.Write([]byte("ok"))
	})
	now := time.Now()
	mux, originServer, tokenServer, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: "stale-token", expiresAt: now.Add(time.Hour)},
		tokenResponse{token: "fresh-token", expiresAt: now.Add(2 * time.Hour)},
	)

	req := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/pypi/repository/simple/pkg/"), nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
	assert.Equal(t, int32(2), requests.Load())
	assert.Equal(t, 2, tokenServer.requestCount())
}

func TestCodeArtifactReturnsSecondAuthorizationFailure(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "denied", http.StatusForbidden)
	})
	now := time.Now()
	mux, originServer, tokenServer, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: "token-1", expiresAt: now.Add(time.Hour)},
		tokenResponse{token: "token-2", expiresAt: now.Add(2 * time.Hour)},
	)

	req := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/generic/repository/file"), nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "denied\n", w.Body.String())
	assert.Equal(t, "30", w.Header().Get("Retry-After"))
	assert.Equal(t, int32(2), requests.Load(), "authorization failure must have only one retry")
	assert.Equal(t, 2, tokenServer.requestCount())
}

func TestCodeArtifactTokenRefreshesCoalesce(t *testing.T) {
	now := time.Now()
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "token-1", expiresAt: now.Add(time.Hour)},
		tokenResponse{token: "token-1", expiresAt: now.Add(2 * time.Hour)},
	)
	manager := tokenServer.tokenManager(func() time.Time { return now })

	const callers = 16
	start := make(chan struct{})
	tokens := make(chan string, callers)
	errorsCh := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			token, err := manager.Token(t.Context(), 0)
			tokens <- token.value
			errorsCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(tokens)
	close(errorsCh)

	for err := range errorsCh {
		assert.NoError(t, err)
	}
	for token := range tokens {
		assert.Equal(t, "token-1", token)
	}
	assert.Equal(t, 1, tokenServer.requestCount())

	start = make(chan struct{})
	tokens = make(chan string, callers)
	errorsCh = make(chan error, callers)
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			token, err := manager.Token(t.Context(), 1)
			tokens <- token.value
			errorsCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(tokens)
	close(errorsCh)

	for err := range errorsCh {
		assert.NoError(t, err)
	}
	for token := range tokens {
		assert.Equal(t, "token-1", token)
	}
	assert.Equal(t, 2, tokenServer.requestCount(), "forced refreshes should coalesce")
}

func TestCodeArtifactRefreshesBeforeExpiration(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "near-expiry", expiresAt: now.Add(time.Minute)},
		tokenResponse{token: "fresh", expiresAt: now.Add(time.Hour)},
	)
	manager := tokenServer.tokenManager(func() time.Time { return now })

	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	second, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)

	assert.Equal(t, "near-expiry", first.value)
	assert.Equal(t, "fresh", second.value)
	assert.Equal(t, 2, tokenServer.requestCount())
}

func TestCodeArtifactRefreshFailureFallsBackOnlyToUnrejectedToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "near-expiry", expiresAt: now.Add(time.Minute)},
		tokenResponse{status: http.StatusServiceUnavailable},
	)
	manager := tokenServer.tokenManager(func() time.Time { return now })

	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	fallback, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	assert.Equal(t, first.value, fallback.value)
	assert.Equal(t, first.generation, fallback.generation)
	assert.Equal(t, codeArtifactAuthReuse, fallback.event)

	_, err = manager.Token(t.Context(), first.generation)
	assert.Error(t, err)
}

func TestCodeArtifactDeniesWritesBeforeOrigin(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux, originServer, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	path := codeArtifactPath(originServer, "/maven/repository/package")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, path, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, method)
	}
	assert.Equal(t, int32(0), requests.Load())
}

func TestCodeArtifactRewritesSameOriginAndFollowsCrossOriginRedirects(t *testing.T) {
	type observedDownload struct {
		authorization      string
		proxyAuthorization string
		cookie             string
		packageAuth        string
		rangeHeader        string
		ifNoneMatch        string
		acceptEncoding     string
		rawQuery           string
	}
	var downloadRequest observedDownload
	download := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloadRequest = observedDownload{
			authorization:      r.Header.Get("Authorization"),
			proxyAuthorization: r.Header.Get("Proxy-Authorization"),
			cookie:             r.Header.Get("Cookie"),
			packageAuth:        r.Header.Get("X-Package-Authorization"),
			rangeHeader:        r.Header.Get("Range"),
			ifNoneMatch:        r.Header.Get("If-None-Match"),
			acceptEncoding:     r.Header.Get("Accept-Encoding"),
			rawQuery:           r.URL.RawQuery,
		}
		_, _ = w.Write([]byte("asset"))
	}))
	t.Cleanup(download.Close)

	var originURL string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, originURL+"/maven/repository/final?download=1", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, download.URL+"/asset?X-Amz-Signature=secret", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), cache.NoOpCache(), true)
	assert.NoError(t, err)
	strategy.client.Transport = download.Client().Transport
	originURL = originServer.URL

	same := httptest.NewRecorder()
	mux.ServeHTTP(same, httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/same"), nil).WithContext(ctx))
	assert.Equal(t, http.StatusFound, same.Code)
	assert.Equal(t, codeArtifactPath(originServer, "/maven/repository/final?download=1"), same.Header().Get("Location"))

	crossRequest := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/cross"), nil).WithContext(ctx)
	crossRequest.Header.Set("Authorization", "Bearer client-token")
	crossRequest.Header.Set("Proxy-Authorization", "Basic client-proxy-token")
	crossRequest.Header.Set("Cookie", "session=client-secret")
	crossRequest.Header.Set("X-Package-Authorization", "client-package-token")
	crossRequest.Header.Set("Range", "bytes=0-4")
	crossRequest.Header.Set("If-None-Match", `"asset-v1"`)
	crossRequest.Header.Set("Accept-Encoding", "gzip")
	cross := httptest.NewRecorder()
	mux.ServeHTTP(cross, crossRequest)
	assert.Equal(t, http.StatusOK, cross.Code)
	assert.Equal(t, "asset", cross.Body.String())
	assert.Equal(t, "", cross.Header().Get("Location"))
	assert.Equal(t, observedDownload{
		authorization:      "",
		proxyAuthorization: "",
		cookie:             "",
		packageAuth:        "",
		rangeHeader:        "bytes=0-4",
		ifNoneMatch:        `"asset-v1"`,
		acceptEncoding:     "gzip",
		rawQuery:           "X-Amz-Signature=secret",
	}, downloadRequest)
}
