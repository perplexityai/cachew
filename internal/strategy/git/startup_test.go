package git_test

import (
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/gitclone"
	"github.com/block/cachew/internal/githubapp"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/git"
)

func startupOrigin(t *testing.T, root string, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	bin, err := exec.LookPath("git")
	assert.NoError(t, err)
	server := httptest.NewTLSServer(wrap(&cgi.Handler{
		Path: bin, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=true"},
	}))
	t.Cleanup(server.Close)
	t.Setenv("GIT_SSL_NO_VERIFY", "true")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	return server.URL
}

func TestStartupRetriesOnlyMirrorsThatFailed(t *testing.T) {
	root, mirrors := t.TempDir(), t.TempDir()
	var allow atomic.Bool
	var failures, healthy atomic.Int32
	origin := startupOrigin(t, root, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/a/") && !allow.Load() {
				failures.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path == "/b/info/refs" {
				healthy.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	host := strings.TrimPrefix(origin, "https://")
	for _, name := range []string{"a", "b"} {
		up := filepath.Join(root, name)
		runInfoRefsGit(t, "init", "-b", "main", up)
		runInfoRefsGit(t, "-C", up, "config", "user.name", "Test")
		runInfoRefsGit(t, "-C", up, "config", "user.email", "test@example.com")
		runInfoRefsGit(t, "-C", up, "commit", "--allow-empty", "-m", "seed")
		runInfoRefsGit(t, "clone", "--mirror", up, filepath.Join(mirrors, host, name))
		runInfoRefsGit(t, "-C", up, "commit", "--allow-empty", "-m", "advance")
	}
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	cm := gitclone.NewManagerProvider(ctx, gitclone.Config{MirrorRoot: mirrors}, nil)
	s, err := git.New(ctx, git.Config{}, newTestScheduler(ctx, t), nil, newTestMux(), cm,
		func() (*githubapp.TokenManager, error) { return nil, nil }, newTestSpools(t)) //nolint:nilnil
	assert.NoError(t, err)
	waitForColdCondition(t, func() bool { return failures.Load() >= 2 && healthy.Load() > 0 })
	assert.False(t, s.Ready())
	before := healthy.Load()
	allow.Store(true)
	waitForReady(t, s)
	assert.Equal(t, before, healthy.Load())
	for _, name := range []string{"a", "b"} {
		assert.Equal(t, runInfoRefsGit(t, "-C", filepath.Join(root, name), "rev-parse", "HEAD"),
			runInfoRefsGit(t, "-C", filepath.Join(mirrors, host, name), "rev-parse", "HEAD"))
	}
}
