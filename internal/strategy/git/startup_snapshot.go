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

const startupProbeInterval = 5 * time.Second
const startupProbeTimeout = 3 * time.Second

// Keep the claim and the restored objects across origin outages. Only discard
// the seed when Git independently identifies a local connectivity error.
func (s *Strategy) retryStartupRestore(ctx context.Context, repo *gitclone.Repository, fetchErr error) error {
	timeout := s.cloneManager.Config().CloneTimeout
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	integrityErr := repo.ConnectivityFailure(checkCtx)
	cancel()
	if integrityErr != nil {
		return errors.WithStack(integrityErr)
	}
	for delay := time.Second; ; delay = min(2*delay, 30*time.Second) {
		logging.FromContext(ctx).WarnContext(ctx, "Retaining restored mirror; retrying startup fetch", "upstream", repo.UpstreamURL(), "error", fetchErr)
		select {
		case <-ctx.Done():
			return errors.WithStack(ctx.Err())
		case <-time.After(delay):
		}
		fetchErr = repo.FetchLenient(ctx, timeout)
		if fetchErr == nil {
			return nil
		}
	}
}

func (s *Strategy) qualifySnapshotStartup(ctx context.Context) (*gitclone.Repository, bool) {
	up := s.config.StartupSnapshotRepository
	var bootstrapped *gitclone.Repository
	for delay := time.Second; ctx.Err() == nil; delay = min(2*delay, 30*time.Second) {
		repo, err := s.cloneManager.GetOrCreate(ctx, up)
		if err == nil && repo.State() != gitclone.StateReady {
			err = s.bootstrapMirror(ctx, repo, bootstrapAtStartup)
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
	tick := time.NewTicker(startupProbeInterval)
	defer tick.Stop()
	for {
		start := time.Now()
		probeCtx, cancel := context.WithTimeout(ctx, startupProbeTimeout)
		if s.readableStartupSnapshot(probeCtx, key) && probeCtx.Err() == nil {
			until := start.Add(startupProbeInterval + startupProbeTimeout)
			s.snapshotProbeUntil.Store(&until)
		} else {
			s.snapshotProbeUntil.Store(nil)
		}
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
