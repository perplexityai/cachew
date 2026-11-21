package git //nolint:testpackage // Drive the probe clock independently of Git subprocesses.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
)

type stalledProbeCache struct {
	cache.Cache
	opened bool
	stall  chan struct{}
}

func (c *stalledProbeCache) Open(ctx context.Context, key cache.Key, opts ...cache.Option) (io.ReadCloser, http.Header, error) {
	if c.opened {
		<-c.stall
	}
	c.opened = true
	return c.Cache.Open(ctx, key, opts...) //nolint:wrapcheck // Preserve backend behavior.
}

func TestStalledProbeCannotExtendEarlyReadiness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, base := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
		ctx, cancel := context.WithCancel(base)
		defer cancel()
		mem, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
		assert.NoError(t, err)
		c := &stalledProbeCache{Cache: mem, stall: make(chan struct{})}
		defer close(c.stall)
		s := &Strategy{config: Config{StartupSnapshotRepository: "https://example.test/repo"}, cache: c}
		w, err := mem.Create(ctx, snapshotCacheKey(s.config.StartupSnapshotRepository),
			http.Header{"X-Cachew-Snapshot-Commit": {strings.Repeat("a", 40)}}, time.Hour)
		assert.NoError(t, err)
		_, err = w.Write([]byte("archive"))
		assert.NoError(t, err)
		assert.NoError(t, w.Close())
		go s.watchStartupSnapshot(ctx)
		synctest.Wait()
		assert.True(t, s.Ready())
		time.Sleep(startupProbeInterval + startupProbeTimeout)
		synctest.Wait()
		assert.False(t, s.Ready())
	})
}
