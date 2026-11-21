package git

import (
	"context"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/gitclone"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
)

func (s *Strategy) qualifySnapshotStartup(ctx context.Context) (*gitclone.Repository, bool) {
	up := s.config.StartupSnapshotRepository
	var bootstrapped *gitclone.Repository
	for delay := time.Second; ctx.Err() == nil; delay = min(2*delay, 30*time.Second) {
		repo, err := s.cloneManager.GetOrCreate(ctx, up)
		if err == nil && repo.State() != gitclone.StateReady {
			err = s.bootstrapMirror(ctx, repo, false)
			if err == nil && repo.State() == gitclone.StateReady {
				bootstrapped = repo
			}
		}
		if err == nil && repo.State() == gitclone.StateReady {
			err = repo.FetchSnapshotHead(ctx)
			if err == nil {
				logging.FromContext(ctx).InfoContext(ctx, "Fetched startup snapshot HEAD", "upstream", up)
				return bootstrapped, true
			}
		}
		logging.FromContext(ctx).WarnContext(ctx, "Startup snapshot repository not qualified; retrying", "upstream", up, "error", err)
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(delay):
		}
	}
	return nil, false
}

func (s *Strategy) watchStartupSnapshot(ctx context.Context) {
	key := snapshotCacheKey(s.config.StartupSnapshotRepository)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		s.snapshotReady.Store(s.readableStartupSnapshot(probeCtx, key))
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Strategy) readableStartupSnapshot(ctx context.Context, key cache.Key) bool {
	body, headers, err := cache.OpenProbeByte(ctx, s.cache, key)
	if body == nil {
		return false
	}
	defer body.Close()
	total, ok := strings.CutPrefix(headers.Get("Content-Range"), "bytes 0-0/")
	n, parseErr := strconv.ParseInt(total, 10, 64)
	_, tagErr := cache.RawETagFromHeader(headers.Get("ETag"))
	if err != nil || !ok || n <= 0 || parseErr != nil || tagErr != nil || headers.Get("Content-Length") != "1" ||
		!commitSHARe.MatchString(headers.Get("X-Cachew-Snapshot-Commit")) {
		return false
	}
	var first [1]byte
	_, err = io.ReadFull(body, first[:])
	return err == nil
}

func (s *Strategy) serveStartupSnapshot(w http.ResponseWriter, r *http.Request, host, path string) {
	up := s.config.StartupSnapshotRepository
	ctx := r.Context()
	if (r.Method == http.MethodHead || r.Method == http.MethodGet) && "https://"+host+"/"+path == up+"/snapshot.tar.zst" {
		key, name, start := snapshotCacheKey(up), strings.TrimPrefix(up, "https://"), time.Now()
		s.metrics.recordRequest(ctx, "snapshot")
		if r.Method == http.MethodHead {
			s.serveSnapshotHead(ctx, w, r, key, name, start)
			return
		}
		body, headers, err := s.cache.Open(ctx, key, httputil.ConditionalOptions(r)...)
		if !errors.Is(err, os.ErrNotExist) {
			served, serveErr := s.serveOpenedSnapshot(ctx, w, body, headers, err, name, "cold_cache", start)
			if serveErr != nil {
				logging.FromContext(ctx).WarnContext(ctx, "Could not serve startup snapshot", "error", serveErr)
			}
			if served {
				return
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "1")
	http.Error(w, "Git mirror warm-up in progress", http.StatusServiceUnavailable)
}
