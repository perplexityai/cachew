package strategy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
)

// A caller that is rate limited retries with another credential, so one
// credential's 429 must not pause the host for the next.
func TestGitHubObjectsCoolsDownPerCredential(t *testing.T) {
	const (
		limitedToken = "Bearer limited"
		treeSHA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == limitedToken {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": map[string]any{
			"root": map[string]string{"__typename": "Tree", "oid": treeSHA},
			"o0":   map[string]string{"__typename": "Blob", "oid": strings.Repeat("b", 40)},
		}}})
	}))
	defer upstream.Close()

	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer memory.Close()
	mux := http.NewServeMux()
	httputil.SetUpstreamTransport(httputil.NewBackoffTransport(http.DefaultTransport, time.Minute, time.Hour, slog.New(slog.DiscardHandler)))
	t.Cleanup(func() { httputil.SetUpstreamTransport(nil) })
	_, err = NewGitHubObjects(ctx, GitHubObjectsConfig{Target: upstream.URL}, memory, mux)
	assert.NoError(t, err)

	post := func(authorization string) int {
		t.Helper()
		body := `{"tree_sha":"` + treeSHA + `","paths":["OWNERS.yaml"]}`
		request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api.github.com/repos/org/repo/git/objects:batch", strings.NewReader(body))
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response.Code
	}
	assert.Equal(t, http.StatusTooManyRequests, post(limitedToken))
	assert.Equal(t, http.StatusTooManyRequests, post(limitedToken))
	assert.Equal(t, int32(1), calls.Load(), "the limited credential is not retried during its cooldown")
	assert.Equal(t, http.StatusOK, post("Bearer alternate"), "a retry with another credential reaches the upstream")
	assert.Equal(t, int32(2), calls.Load())
}
