package strategy //nolint:testpackage // Exercise origin transport and token boundaries without AWS.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/opa"
)

func TestCodeArtifactAliases(t *testing.T) {
	for _, aliasesOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("aliases-only=%t", aliasesOnly), func(t *testing.T) {
			calls := 0
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, "/maven/downloads/org/example/tool/sha256-abc/tool-sha256-abc.tar", r.URL.Path)
				user, token, ok := r.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "aws", user)
				assert.Equal(t, "token", token)
				w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
				w.Header().Set("Content-Length", "7")
				_, _ = w.Write([]byte("archive"))
			}))
			defer origin.Close()
			_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
			memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
			assert.NoError(t, err)
			defer memory.Close()
			tokens := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
			config := testCodeArtifactConfig(origin.URL)
			config.AliasesOnly = aliasesOnly
			config.Aliases = []CodeArtifactAliasConfig{{
				Pattern: "/downloads/{tool}/{digest}",
				Path:    "/maven/downloads/org/example/{tool}/sha256-{digest}/{tool}-sha256-{digest}.tar",
			}}
			mux := http.NewServeMux()
			_, err = newCodeArtifact(ctx, config, mux, tokens.tokenManager(time.Now), memory, true)
			assert.NoError(t, err)
			handler, err := opa.Middleware(ctx, opa.Config{Policy: `package cachew.authz
default allow := false
allow if {
    input.path == ["downloads", "tool", "abc"]
    input.headers["authorization"] == "Bearer client-token"
}
`}, mux)
			assert.NoError(t, err)
			for range 2 {
				denied := httptest.NewRecorder()
				handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/downloads/tool/abc", nil).WithContext(ctx))
				assert.Equal(t, http.StatusForbidden, denied.Code)
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, "/downloads/tool/abc", nil).WithContext(ctx)
				r.Header.Set("Authorization", "Bearer client-token")
				handler.ServeHTTP(w, r)
				assert.Equal(t, "/downloads/tool/abc", r.URL.Path)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, "archive", w.Body.String())
			}
			assert.Equal(t, 1, calls)
			for _, url := range []string{
				"/downloads/tool/abc?token=value",
				"/downloads/tool/abc?",
				"/downloads/tool/%2e%2e",
				"/downloads/tool/%61bc",
				"/downloads/tool/abc%2fhidden",
				"/downloads/tool/abc%25hidden",
			} {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil).WithContext(ctx))
				assert.Equal(t, http.StatusNotFound, w.Code, "url=%s", url)
			}
			assert.Equal(t, 1, calls)
			direct := httptest.NewRecorder()
			mux.ServeHTTP(direct, httptest.NewRequest(http.MethodGet,
				codeArtifactPath(origin, "/maven/downloads/org/example/tool/sha256-abc/tool-sha256-abc.tar"), nil).WithContext(ctx))
			if aliasesOnly {
				assert.Equal(t, http.StatusNotFound, direct.Code)
			} else {
				assert.Equal(t, http.StatusOK, direct.Code)
				assert.Equal(t, "archive", direct.Body.String())
			}
			assert.Equal(t, 1, calls)
			head := httptest.NewRecorder()
			mux.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/downloads/tool/abc", nil).WithContext(ctx))
			assert.Equal(t, http.StatusOK, head.Code)
			assert.Equal(t, "", head.Body.String())
			write := httptest.NewRecorder()
			mux.ServeHTTP(write, httptest.NewRequest(http.MethodPost, "/downloads/tool/abc", nil).WithContext(ctx))
			assert.Equal(t, http.StatusMethodNotAllowed, write.Code)
		})
	}
}

func TestCodeArtifactAliasRejectsUnsafeConfiguration(t *testing.T) {
	for _, alias := range []CodeArtifactAliasConfig{
		{Pattern: "/downloads/{name}", Path: "https://example.com/{name}"},
		{Pattern: "/downloads/{name}", Path: "/maven/{unknown}"},
		{Pattern: "/downloads/{name}", Path: "/maven/../{name}"},
		{Pattern: "/downloads/{name}", Path: "/maven/{name}?secret=x"},
		{Pattern: "/downloads/{name...}", Path: "/maven/{name}"},
		{Pattern: "/downloads/{name}/{name}", Path: "/maven/{name}"},
	} {
		_, err := validateCodeArtifactAlias(alias)
		assert.Error(t, err)
	}
}
