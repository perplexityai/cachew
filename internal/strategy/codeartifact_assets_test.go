package strategy //nolint:testpackage // Exercise the SDK transport and cache without AWS.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	assert.Equal(t, 200, ranged.Code)
	assert.Equal(t, "archive", ranged.Body.String())
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
		assert.Equal(t, "bad", request("GET", "truncated.tar", nil).Body.String())
	}
	assert.Equal(t, 12, calls)
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
