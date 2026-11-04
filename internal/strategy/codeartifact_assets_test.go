package strategy //nolint:testpackage // Exercise the SDK transport and cache without AWS.

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/opa"
)

func TestCodeArtifactAssetAPI(t *testing.T) {
	calls := 0
	wantDomain := "example"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "/v1/package/version/asset", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, wantDomain, r.URL.Query().Get("domain"))
		assert.Equal(t, "123456789012", r.URL.Query().Get("domain-owner"))
		assert.Equal(t, "packages", r.URL.Query().Get("repository"))
		assert.Equal(t, "org.example", r.URL.Query().Get("namespace"))
		assert.Equal(t, "maven", r.URL.Query().Get("format"))
		assert.Equal(t, "tool", r.URL.Query().Get("package"))
		assert.Equal(t, "1", r.URL.Query().Get("version"))
		assert.Contains(t, r.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
		assert.NotEqual(t, "Bearer caller", r.Header.Get("Authorization"))
		switch r.URL.Query().Get("asset") {
		case "missing.tar":
			w.Header().Set("X-Amzn-Errortype", "ResourceNotFoundException")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"missing"}`))
		case "denied.tar":
			w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"private origin detail"}`))
		case "truncated.tar":
			w.Header().Set("Content-Length", "7")
			_, _ = w.Write([]byte("bad"))
		default:
			w.Header().Set("X-Packageversionrevision", "revision-1")
			w.Header().Set("Content-Length", "7")
			w.Header().Set("X-Secret", "not-for-client")
			_, _ = w.Write([]byte("archive"))
		}
	}))
	defer origin.Close()
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer memory.Close()
	config := testCodeArtifactConfig(origin.URL)
	config.AssetAPI = true
	config.ProxyBaseURL = ""
	config.ImmutableFallbackTTL = time.Hour
	config.Aliases = []CodeArtifactAliasConfig{{Pattern: "/downloads/{version}/{asset}", Path: "/maven/packages/org/example/tool/{version}/{asset}"}}
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, config, mux, nil, memory, true)
	assert.NoError(t, err)
	metrics := &recordingCodeArtifactMetrics{}
	strategy.metric = metrics
	strategy.assets = &codeArtifactAssetOrigin{
		domain: "example", owner: "123456789012",
		client: awscodeartifact.NewFromConfig(aws.Config{
			Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("fixture", "fixture", ""),
		}, func(o *awscodeartifact.Options) { o.BaseEndpoint = aws.String(origin.URL); o.RetryMaxAttempts = 1 }),
	}
	handler, err := opa.Middleware(ctx, opa.Config{Policy: `package cachew.authz
default allow := false
allow if { input.headers["authorization"] == "Bearer caller" }
`}, mux)
	assert.NoError(t, err)
	request := func(method, asset string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/downloads/1/"+asset, nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer caller")
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		denied := httptest.NewRecorder()
		handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/downloads/1/tool.tar", nil).WithContext(ctx))
		assert.Equal(t, http.StatusForbidden, denied.Code)
		handler.ServeHTTP(w, r)
		return w
	}
	first := request("GET", "tool.tar", nil)
	assert.Equal(t, 200, first.Code)
	assert.Equal(t, "archive", first.Body.String())
	assert.Equal(t, "7", first.Header().Get("Content-Length"))
	assert.Equal(t, "", first.Header().Get("X-Secret"))
	assert.Equal(t, "archive", request("GET", "tool.tar", nil).Body.String())
	assert.Equal(t, 1, calls)
	etag := first.Header().Get("ETag")
	assert.Equal(t, 304, request("GET", "tool.tar", map[string]string{"If-None-Match": etag}).Code)
	assert.Equal(t, 412, request("GET", "tool.tar", map[string]string{"If-Match": `"other"`}).Code)
	assert.Equal(t, 1, calls)
	for asset, status := range map[string]int{"missing.tar": http.StatusNotFound, "denied.tar": http.StatusForbidden} {
		for range 2 {
			response := request("GET", asset, nil)
			assert.Equal(t, status, response.Code)
			assert.Equal(t, "CodeArtifact asset unavailable\n", response.Body.String())
		}
	}
	assert.Equal(t, 5, calls)
	head := request("HEAD", "cold.tar", nil)
	assert.Equal(t, 200, head.Code)
	assert.Equal(t, "", head.Body.String())
	assert.Equal(t, "7", head.Header().Get("Content-Length"))
	assert.Equal(t, 304, request("GET", "cold.tar", map[string]string{"If-None-Match": etag}).Code)
	ranged := request("GET", "cold.tar", map[string]string{"Range": "bytes=0-1"})
	assert.Equal(t, 206, ranged.Code)
	assert.Equal(t, "ar", ranged.Body.String())
	assert.Equal(t, "bytes 0-1/7", ranged.Header().Get("Content-Range"))
	assert.Equal(t, "2", ranged.Header().Get("Content-Length"))
	assert.Equal(t, 8, calls)
	assert.Equal(t, "archive", request("GET", "cold.tar", nil).Body.String())
	assert.Equal(t, 9, calls)
	snapshot := httptest.NewRecorder()
	mux.ServeHTTP(snapshot, httptest.NewRequest(http.MethodGet, "/downloads/1-SNAPSHOT/tool.tar", nil))
	assert.Equal(t, 404, snapshot.Code)
	assert.Equal(t, 9, calls)
	for _, path := range []string{
		"/downloads/1/tool.tar?token=value", "/downloads/1/tool.tar?",
		"/downloads/1/%2e%2e", "/downloads/1/%61bc", "/downloads/1/a%2fb", "/downloads/1/a%25b",
		codeArtifactPath(origin, "/maven/packages/org/example/tool/1/tool.tar"),
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusNotFound, w.Code, "path=%s", path)
	}
	assert.Equal(t, http.StatusMethodNotAllowed, request(http.MethodPost, "tool.tar", nil).Code)
	assert.Equal(t, 9, calls)
	wantDomain = "another"
	otherMux := http.NewServeMux()
	config.Domain = wantDomain
	other, err := newCodeArtifact(ctx, config, otherMux, nil, memory, true)
	assert.NoError(t, err)
	other.assets = &codeArtifactAssetOrigin{client: strategy.assets.client, domain: wantDomain, owner: config.DomainOwner}
	otherResponse := httptest.NewRecorder()
	otherMux.ServeHTTP(otherResponse, httptest.NewRequest(http.MethodGet, "/downloads/1/tool.tar", nil).WithContext(ctx))
	assert.Equal(t, http.StatusOK, otherResponse.Code)
	assert.Equal(t, 10, calls)
	wantDomain = "example"
	for range 2 {
		assertCodeArtifactStreamAborted(t, func() {
			request("GET", "truncated.tar", nil)
		})
	}
	assert.Equal(t, 12, calls)
	for _, tc := range []struct {
		name, rangeHeader, ifRange, contentRange, body string
		status                                         int
	}{
		{"resume", "bytes=2-", "", "bytes 2-6/7", "chive", 206},
		{"suffix", "bytes=-3", "", "bytes 4-6/7", "ive", 206},
		{"matching validator", "bytes=1-2", etag, "bytes 1-2/7", "rc", 206},
		{"changed validator", "bytes=1-2", `"other"`, "", "archive", 200},
		{"past end", "bytes=7-", "", "bytes */7", "", 416},
		{"multiple ranges", "bytes=0-1,4-5", "", "", "archive", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := request("GET", "tool.tar", map[string]string{"Range": tc.rangeHeader, "If-Range": tc.ifRange})
			assert.Equal(t, tc.status, response.Code)
			assert.Equal(t, tc.body, response.Body.String())
			assert.Equal(t, tc.contentRange, response.Header().Get("Content-Range"))
			assert.Equal(t, strconv.Itoa(len(tc.body)), response.Header().Get("Content-Length"))
			assert.Equal(t, "bytes", response.Header().Get("Accept-Ranges"))
			assert.Equal(t, 12, calls)
		})
	}
	conditionalRange := map[string]string{"Range": "bytes=0-1", "If-None-Match": etag}
	response := request("GET", "tool.tar", conditionalRange)
	assert.Equal(t, 304, response.Code)
	assert.Equal(t, recordedCodeArtifactCacheEvent{event: codeArtifactCacheHit, tier: codeArtifactCacheTierUnknown}, metrics.cache[len(metrics.cache)-1])
	assert.Equal(t, "7", response.Header().Get("Content-Length"))
	assert.Equal(t, "", response.Header().Get("Content-Range"))
	assert.Equal(t, 304, request("GET", "tool.tar", map[string]string{"Range": "bytes=99-", "If-None-Match": "W/" + etag}).Code)
	assert.Equal(t, 412, request("GET", "tool.tar", map[string]string{"Range": "bytes=99-", "If-Match": `"other"`}).Code)
	assert.Equal(t, 12, calls)
	for _, bypass := range []string{"Cache-Control", "Pragma"} {
		before := calls
		response = request("GET", "tool.tar", map[string]string{"Range": "bytes=0-1", bypass: "no-cache"})
		assert.Equal(t, 206, response.Code)
		assert.Equal(t, "ar", response.Body.String())
		assert.Equal(t, before+1, calls)
	}
	head = request("HEAD", "tool.tar", map[string]string{"Range": "bytes=0-1"})
	assert.Equal(t, 200, head.Code)
	assert.Equal(t, "7", head.Header().Get("Content-Length"))
	assert.Equal(t, "", head.Header().Get("Content-Range"))
	assert.Equal(t, "", head.Body.String())
	assertCodeArtifactStreamAborted(t, func() {
		request("GET", "truncated.tar", map[string]string{"Range": "bytes=0-5"})
	})
	assertCodeArtifactStreamAborted(t, func() {
		request("GET", "truncated.tar", map[string]string{"Range": "bytes=5-6"})
	})
	beforeRetry := calls
	assertCodeArtifactStreamAborted(t, func() { request("GET", "truncated.tar", nil) })
	assert.Equal(t, beforeRetry+1, calls)
	assert.Equal(t, "archive", request("GET", "tool.tar", nil).Body.String())
	var failureLogs bytes.Buffer
	strategy.logger = slog.New(slog.NewJSONHandler(&failureLogs, nil))
	for _, tc := range []struct {
		span              string
		written, expected float64
	}{
		{"bytes=1-5", 2, 5},
		{"bytes=2-", 1, 5},
		{"bytes=5-", 0, 2},
	} {
		failureLogs.Reset()
		assertCodeArtifactStreamAborted(t, func() {
			request("GET", "truncated.tar", map[string]string{"Range": tc.span})
		})
		entries := codeArtifactFailureLogs(t, failureLogs.Bytes())
		entry := entries[len(entries)-1]
		assert.Equal[any](t, tc.written, entry["bytes_written"])
		assert.Equal[any](t, tc.expected, entry["expected_bytes"])
	}
	for _, tc := range []struct {
		asset, span, body string
		status            int
	}{
		{"resume.tar", "bytes=2-", "chive", 206},
		{"suffix.tar", "bytes=-3", "ive", 206},
		{"entire.tar", "bytes=0-", "archive", 206},
		{"bounded-eof.tar", "bytes=2-6", "chive", 206},
		{"bounded-past-eof.tar", "bytes=0-99999999", "archive", 206},
		{"multi.tar", "bytes=0-1,4-5", "archive", 200},
		{"invalid.tar", "bytes=a-b", "archive", 200},
	} {
		before := calls
		partial := request("GET", tc.asset, map[string]string{"Range": tc.span})
		assert.Equal(t, tc.status, partial.Code)
		assert.Equal(t, tc.body, partial.Body.String())
		assert.Equal(t, "archive", request("GET", tc.asset, nil).Body.String())
		assert.Equal(t, before+1, calls)
	}
	before := calls
	strategy.immutableFallbackTTL = 0
	response = request("GET", "tool.tar", map[string]string{"Range": "bytes=99-", "If-None-Match": etag})
	assert.Equal(t, 304, response.Code)
	assert.Equal(t, before+1, calls)
}

func TestCodeArtifactAssetConfiguration(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	for _, tc := range []struct {
		name      string
		configure func(*CodeArtifactConfig)
		valid     bool
	}{
		{"no metadata rewrite URL", func(c *CodeArtifactConfig) { c.ProxyBaseURL = "" }, true},
		{"repository still requires rewrite URL", func(c *CodeArtifactConfig) { c.AssetAPI = false; c.Aliases = nil }, false},
		{"rejects unused rewrite URL", func(c *CodeArtifactConfig) { c.ProxyBaseURL = "https://cachew.example.com" }, false},
		{"rejects repository aliases", func(c *CodeArtifactConfig) { c.AssetAPI = false; c.ProxyBaseURL = "https://cachew.example.com" }, false},
		{"requires aliases", func(c *CodeArtifactConfig) { c.Aliases = nil }, false},
		{"rejects npm", func(c *CodeArtifactConfig) { c.Aliases[0].Path = "/npm/packages/{version}/{asset}" }, false},
		{"rejects incomplete Maven path", func(c *CodeArtifactConfig) { c.Aliases[0].Path = "/maven/packages/{version}/{asset}" }, false},
		{"rejects static snapshot", func(c *CodeArtifactConfig) { c.Aliases[0].Path = "/maven/packages/org/tool/1-SNAPSHOT/{asset}" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testCodeArtifactConfig("https://codeartifact.example.com")
			config.AssetAPI, config.ProxyBaseURL = true, ""
			config.Aliases = []CodeArtifactAliasConfig{{Pattern: "/downloads/{version}/{asset}", Path: "/maven/packages/org/example/tool/{version}/{asset}"}}
			tc.configure(&config)
			_, err := newCodeArtifact(ctx, config, http.NewServeMux(), nil, cache.NoOpCache(), false)
			if tc.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCodeArtifactAssetCredentialDeadline(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_MAX_ATTEMPTS", "100")
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ServiceUnavailable</Code></Error></ErrorResponse>`))
	}))
	defer sts.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)
	config := testCodeArtifactConfig("https://codeartifact.example.com")
	config.AssetAPI = true
	config.CredentialTimeout = 10 * time.Millisecond
	client, err := newCodeArtifactClient(t.Context(), config)
	assert.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = client.Options().Credentials.Retrieve(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	assert.NoError(t, ctx.Err(), "credential timeout must include STS retries, before the caller deadline")
}
