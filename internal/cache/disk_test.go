package cache_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/cache/cachetest"
	"github.com/block/cachew/internal/logging"
)

func TestDiskCache(t *testing.T) {
	cachetest.Suite(t, func(t *testing.T) cache.Cache {
		dir := t.TempDir()
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		c, err := cache.NewDisk(ctx, cache.DiskConfig{
			Root:   dir,
			MaxTTL: 3 * time.Second,
		})
		assert.NoError(t, err)
		return c
	})
}

func TestDiskRejectsInvalidReadIsolationConfig(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	tests := []struct {
		name   string
		config cache.DiskConfig
	}{
		{name: "negative concurrency", config: cache.DiskConfig{ReadConcurrency: -1}},
		{name: "excessive concurrency", config: cache.DiskConfig{ReadConcurrency: 4097}},
		{name: "negative operation timeout", config: cache.DiskConfig{OperationTimeout: -1}},
		{name: "negative read idle timeout", config: cache.DiskConfig{ReadIdleTimeout: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Root = t.TempDir()
			_, err := cache.NewDisk(ctx, tt.config)
			assert.Error(t, err)
		})
	}
}

func TestDiskCacheSoak(t *testing.T) {
	if os.Getenv("SOAK_TEST") == "" {
		t.Skip("Skipping soak test; set SOAK_TEST=1 to run")
	}

	dir := t.TempDir()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewDisk(ctx, cache.DiskConfig{
		Root:          dir,
		LimitMB:       50,
		MaxTTL:        10 * time.Minute,
		EvictInterval: time.Second,
	})
	assert.NoError(t, err)
	defer c.Close()

	cachetest.Soak(t, c, cachetest.SoakConfig{
		Duration:         time.Minute,
		NumObjects:       500,
		MaxObjectSize:    512 * 1024,
		MinObjectSize:    1024,
		OverwritePercent: 30,
		Concurrency:      8,
		TTL:              5 * time.Minute,
	})
}

func TestDiskOpenRevisionAtomic(t *testing.T) {
	dir := t.TempDir()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewDisk(ctx, cache.DiskConfig{Root: dir, MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer c.Close()

	key := cache.NewKey("revision-atomic")

	write := func(rev int) {
		body := bytes.Repeat([]byte{byte(rev)}, 4096+rev)
		sum := sha256.Sum256(body)
		raw := hex.EncodeToString(sum[:])
		w, err := c.Create(ctx, key, http.Header{}, time.Hour, cache.WithETag(raw))
		if err != nil {
			t.Errorf("create: %v", err)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("write: %v", errors.Join(err, w.Abort(err)))
			return
		}
		if err := w.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}

	write(0)

	const writers, readsPerReader, readers = 4, 500, 4
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range writers {
		wg.Go(func() {
			for rev := 1; ; rev++ {
				select {
				case <-stop:
					return
				default:
				}
				write(rev % 251)
			}
		})
	}

	for range readers {
		wg.Go(func() {
			for range readsPerReader {
				r, headers, err := c.Open(ctx, key)
				if err != nil {
					t.Errorf("open: %v", err)
					continue
				}
				body, err := io.ReadAll(r)
				_ = r.Close()
				if err != nil {
					t.Errorf("read: %v", err)
					continue
				}
				sum := sha256.Sum256(body)
				want, err := cache.FormatETag(hex.EncodeToString(sum[:]))
				if err != nil {
					t.Errorf("format etag: %v", err)
					continue
				}
				if got := headers.Get(cache.ETagKey); got != want {
					t.Errorf("etag/body mismatch: header %s does not match body hash %s (spliced revision)", got, want)
				}
			}
		})
	}

	go func() {
		time.Sleep(time.Second)
		close(stop)
	}()
	wg.Wait()
}

func BenchmarkDiskHit(b *testing.B) {
	_, ctx := logging.Configure(b.Context(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewDisk(ctx, cache.DiskConfig{Root: b.TempDir(), MaxTTL: time.Hour})
	assert.NoError(b, err)
	b.Cleanup(func() { assert.NoError(b, c.Close()) })
	key := cache.NewKey("benchmark-disk-hit")
	body := bytes.Repeat([]byte{0x5a}, 4<<20)
	writer, err := c.Create(ctx, key, http.Header{}, time.Hour)
	assert.NoError(b, err)
	_, err = writer.Write(body)
	assert.NoError(b, err)
	assert.NoError(b, writer.Close())
	read := func(b *testing.B) {
		b.Helper()
		reader, _, err := c.Open(ctx, key)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("Sequential", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		for range b.N {
			read(b)
		}
	})
	b.Run("Parallel", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				read(b)
			}
		})
	})
}
