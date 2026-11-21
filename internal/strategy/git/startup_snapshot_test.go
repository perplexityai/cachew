package git_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/gitclone"
	"github.com/block/cachew/internal/githubapp"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/git"
)

func holdFullStartupFetch(t *testing.T) (entered, release string) {
	t.Helper()
	dir := t.TempDir()
	gitPath, err := exec.LookPath("git")
	assert.NoError(t, err)
	entered, release = filepath.Join(dir, "entered"), filepath.Join(dir, "release")
	t.Setenv("STARTUP_REAL_GIT", gitPath)
	t.Setenv("STARTUP_ENTERED", entered)
	t.Setenv("STARTUP_RELEASE", release)
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "git"), []byte(`#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = --prune ]; then
    touch "$STARTUP_ENTERED"
    while [ ! -f "$STARTUP_RELEASE" ]; do sleep 0.05; done
    break
  fi
done
exec "$STARTUP_REAL_GIT" "$@"
`), 0o750))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return entered, release
}

func TestSnapshotStartupBootstrapsMissingRequiredMirror(t *testing.T) {
	root, mirrors := t.TempDir(), t.TempDir()
	up := filepath.Join(root, "repo")
	createTestMirrorRepo(t, up)
	var available atomic.Bool
	var failures atomic.Int32
	url := startupOrigin(t, root, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !available.Load() {
				failures.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	}) + "/repo"
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	cm := gitclone.NewManagerProvider(ctx, gitclone.Config{MirrorRoot: mirrors}, nil)
	s, err := git.New(ctx, git.Config{SnapshotInterval: time.Hour, StartupSnapshotRepository: url},
		newTestScheduler(ctx, t), c, newTestMux(), cm, func() (*githubapp.TokenManager, error) { return nil, nil }, newTestSpools(t)) //nolint:nilnil
	assert.NoError(t, err)
	s.SetMetadataStore(nil)
	waitForColdCondition(t, func() bool { return failures.Load() > 0 })
	assert.False(t, s.Ready(), "empty discovery cannot qualify a required repository")
	available.Store(true)
	waitForColdCondition(t, s.Ready)
	mirror := filepath.Join(mirrors, strings.TrimPrefix(url, "https://"))
	assert.Equal(t, runInfoRefsGit(t, "-C", up, "rev-parse", "HEAD"), runInfoRefsGit(t, "-C", mirror, "rev-parse", "HEAD"))
}

func TestSnapshotStartupRequiresFetchAndSeparatesMirrorFreshness(t *testing.T) {
	root, mirrors := t.TempDir(), t.TempDir()
	up := filepath.Join(root, "repo")
	var requests atomic.Int32
	var available atomic.Bool
	origin := startupOrigin(t, root, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !available.Load() {
				requests.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	host := strings.TrimPrefix(origin, "https://")
	url, mirror := origin+"/repo", filepath.Join(mirrors, host, "repo")
	runInfoRefsGit(t, "init", "-b", "main", up)
	runInfoRefsGit(t, "-C", up, "config", "user.name", "Test")
	runInfoRefsGit(t, "-C", up, "config", "user.email", "test@example.com")
	runInfoRefsGit(t, "-C", up, "commit", "--allow-empty", "-m", "seed")
	base := runInfoRefsGit(t, "-C", up, "rev-parse", "HEAD")
	runInfoRefsGit(t, "clone", "--mirror", up, mirror)
	runInfoRefsGit(t, "-C", up, "switch", "-c", "new-default")
	runInfoRefsGit(t, "-C", up, "commit", "--allow-empty", "-m", "advance")
	tip := runInfoRefsGit(t, "-C", up, "rev-parse", "HEAD")
	runInfoRefsGit(t, "-C", up, "update-ref", "refs/pull/1/head", tip)
	entered, release := holdFullStartupFetch(t)
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	key := cache.NewKey(url + ".snapshot")
	writePublication := func() {
		w, err := c.Create(ctx, key, http.Header{"X-Cachew-Snapshot-Commit": {base}}, time.Hour)
		assert.NoError(t, err)
		_, err = w.Write([]byte("older checkout"))
		assert.NoError(t, err)
		assert.NoError(t, w.Close())
	}
	writePublication()
	mux := newTestMux()
	cm := gitclone.NewManagerProvider(ctx, gitclone.Config{MirrorRoot: mirrors}, nil)
	s, err := git.New(ctx, git.Config{SnapshotInterval: time.Hour, StartupSnapshotRepository: url},
		newTestScheduler(ctx, t), c, mux, cm, func() (*githubapp.TokenManager, error) { return nil, nil }, newTestSpools(t)) //nolint:nilnil
	assert.NoError(t, err)
	s.SetMetadataStore(nil)
	request := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/git/"+host+"/"+path, nil)
		r.SetPathValue("host", host)
		r.SetPathValue("path", path)
		r.Header.Set("Range", "bytes=1-3")
		w := httptest.NewRecorder()
		mux.handlers["GET /git/{host}/{path...}"].ServeHTTP(w, r)
		return w
	}
	waitForColdCondition(t, func() bool { return requests.Load() >= 2 })
	assert.False(t, s.Ready())
	assert.Equal(t, "lde", request("repo/snapshot.tar.zst").Body.String())
	assert.NoError(t, c.Delete(ctx, key))
	available.Store(true)
	waitForColdCondition(t, func() bool { _, err := os.Stat(entered); return err == nil })
	assert.False(t, s.Ready())
	assert.Equal(t, http.StatusServiceUnavailable, request("repo/snapshot.tar.zst").Code)
	assert.Equal(t, tip, runInfoRefsGit(t, "-C", mirror, "rev-parse", "FETCH_HEAD"))
	assert.Equal(t, tip, runInfoRefsGit(t, "-C", mirror, "rev-parse", "HEAD"))
	assert.Equal(t, "refs/heads/new-default", runInfoRefsGit(t, "-C", mirror, "symbolic-ref", "HEAD"))
	assert.Equal(t, base, runInfoRefsGit(t, "-C", mirror, "rev-parse", "refs/heads/main"))
	assert.Equal(t, "", runInfoRefsGit(t, "-C", mirror, "for-each-ref", "refs/pull"))
	writePublication()
	waitForColdCondition(t, s.Ready)
	for _, path := range []string{"repo/info/refs", "repo/snapshot.bundle", "other/snapshot.tar.zst"} {
		assert.Equal(t, http.StatusServiceUnavailable, request(path).Code)
	}
	res := request("repo/snapshot.tar.zst")
	assert.Equal(t, http.StatusPartialContent, res.Code)
	assert.Equal(t, "lde", res.Body.String())
	assert.NoError(t, os.WriteFile(release, nil, 0o600))
	waitForColdCondition(t, func() bool {
		return runInfoRefsGit(t, "-C", mirror, "for-each-ref", "--format=%(objectname)", "refs/pull/1/head") == tip
	})
	assert.Equal(t, "+refs/*:refs/*", runInfoRefsGit(t, "-C", mirror, "config", "remote.origin.fetch"))
}
