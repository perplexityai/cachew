package strategy_test

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/strategy"
)

func TestArtifactoryResponsePolicy(t *testing.T) {
	for _, tt := range []struct {
		name    string
		headers http.Header
		cached  bool
	}{
		{"fresh", http.Header{"Cache-Control": {"public, max-age=60"}}, true},
		{"shared freshness", http.Header{"Cache-Control": {"s-maxage=60"}}, true},
		{"expires", http.Header{"Expires": {time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)}}, true},
		{"no freshness", http.Header{}, false},
		{"no cache", http.Header{"Cache-Control": {"public, max-age=60, no-cache"}}, false},
		{"no store", http.Header{"Cache-Control": {"public, max-age=60, no-store"}}, false},
		{"private", http.Header{"Cache-Control": {"private, max-age=60"}}, false},
		{"stale", http.Header{"Cache-Control": {"max-age=60"}, "Age": {"120"}}, false},
		{"cookie", http.Header{"Cache-Control": {"max-age=60"}, "Set-Cookie": {"session=a"}}, false},
		{"unknown vary", http.Header{"Cache-Control": {"max-age=60"}, "Vary": {"X-Custom"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				maps.Copy(w.Header(), tt.headers)
				w.Header().Set("ETag", `"origin"`)
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
				_, _ = fmt.Fprintf(w, "version-%d", calls.Add(1))
			}))
			defer origin.Close()
			mux, path := newArtifactoryPolicyProxy(t, origin)
			for i := range 2 {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				want := "version-1"
				if i == 1 && !tt.cached {
					want = "version-2"
				}
				assert.Equal(t, want, w.Body.String())
				assert.Equal(t, `"origin"`, w.Header().Get("ETag"))
				assert.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", w.Header().Get("Last-Modified"))
			}
		})
	}
}

func TestArtifactoryVariantsAndBypasses(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "Accept, Accept-Encoding")
		if r.Header.Get("If-None-Match") != "" {
			w.Header().Set("ETag", `"origin"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("Range") != "" {
			w.Header().Set("Content-Range", "bytes 0-1/4")
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = fmt.Fprintf(w, "%s:%s:%s", r.Method, r.Header.Get("Accept"), r.Header.Get("Authorization"))
	}))
	defer origin.Close()
	mux, path := newArtifactoryPolicyProxy(t, origin)
	for _, accept := range []string{"full", "brief", "full", "brief"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, "GET:"+accept+":", w.Body.String())
		assert.Equal(t, "", w.Header().Get("ETag"))
		assert.Equal(t, "", w.Header().Get("Last-Modified"))
	}
	assert.Equal(t, int32(2), calls.Load())
	for _, header := range []string{"Authorization", "X-JFrog-Art-Api", "Cookie", "Cache-Control", "Pragma", "Range", "If-None-Match"} {
		for range 2 {
			before := calls.Load()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Accept", "full")
			req.Header.Set(header, "test")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			assert.Equal(t, before+1, calls.Load())
			if header == "Range" {
				assert.Equal(t, http.StatusPartialContent, w.Code)
				assert.Equal(t, "bytes 0-1/4", w.Header().Get("Content-Range"))
			}
			if header == "If-None-Match" {
				assert.Equal(t, http.StatusNotModified, w.Code)
				assert.Equal(t, `"origin"`, w.Header().Get("ETag"))
			}
		}
	}
	before := calls.Load()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodHead, path, nil))
	assert.Equal(t, before+1, calls.Load())
	assert.Equal(t, "", w.Body.String())
}

func newArtifactoryPolicyProxy(t *testing.T, origin *httptest.Server) (*http.ServeMux, string) {
	t.Helper()
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	backend, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	mux := http.NewServeMux()
	_, err = strategy.NewArtifactory(ctx, strategy.ArtifactoryConfig{Target: origin.URL}, backend, mux)
	assert.NoError(t, err)
	return mux, "/" + origin.Listener.Addr().String() + "/npm/package"
}

func TestArtifactoryPreservesEncodedPathsAndBodies(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"compressed"`)
		writer := gzip.NewWriter(w)
		_, _ = io.WriteString(writer, r.URL.EscapedPath())
		_ = writer.Close()
	}))
	defer origin.Close()
	mux, path := newArtifactoryPolicyProxy(t, origin)
	for _, suffix := range []string{"%2Fscoped", "/scoped"} {
		before := calls.Load()
		for range 2 {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path+suffix, nil))
			assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
			assert.Equal(t, `"compressed"`, w.Header().Get("ETag"))
			reader, err := gzip.NewReader(w.Body)
			assert.NoError(t, err)
			data, err := io.ReadAll(reader)
			assert.NoError(t, err)
			assert.NoError(t, reader.Close())
			assert.Equal(t, "/npm/package"+suffix, string(data))
		}
		assert.Equal(t, before+1, calls.Load())
	}
}

type artifactoryRecordingCache struct {
	cache.Cache
	keys chan cache.Key
}

func (c *artifactoryRecordingCache) Create(ctx context.Context, key cache.Key, headers http.Header, ttl time.Duration, opts ...cache.Option) (cache.Writer, error) {
	c.keys <- key
	return c.Cache.Create(ctx, key, headers, ttl, opts...) //nolint:wrapcheck // Test boundary delegates to the real backend.
}

func TestArtifactoryFreshnessSurvivesTierPromotion(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	recorded := &artifactoryRecordingCache{Cache: upper, keys: make(chan cache.Key, 4)}
	store := metadatadb.New(ctx, metadatadb.NewMemoryBackend())
	defer store.Close(ctx)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, recorded}, store)
	defer tiered.Close()
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=2")
		_, _ = fmt.Fprintf(w, "version-%d", calls.Add(1))
	}))
	defer origin.Close()
	mux := http.NewServeMux()
	_, err = strategy.NewArtifactory(ctx, strategy.ArtifactoryConfig{Target: origin.URL}, tiered, mux)
	assert.NoError(t, err)
	request := func() string {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+origin.Listener.Addr().String()+"/package", nil).WithContext(ctx))
		return w.Body.String()
	}
	assert.Equal(t, "version-1", request())
	key := <-recorded.keys
	headers, err := upper.Stat(ctx, key)
	assert.NoError(t, err)
	expires, err := time.Parse(time.RFC3339Nano, headers.Get(cache.ExpirationKey))
	assert.NoError(t, err)
	assert.True(t, expires.After(time.Now()) && expires.Before(time.Now().Add(2*time.Second)))
	assert.NoError(t, lower.Delete(ctx, key))
	assert.Equal(t, "version-1", request())
	deadline := time.Now().Add(time.Second)
	for {
		promoted, err := lower.Stat(ctx, key)
		if err == nil {
			assert.Equal(t, headers.Get(cache.ExpirationKey), promoted.Get(cache.ExpirationKey))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tier promotion did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	assert.Equal(t, "version-2", request())
	assert.Equal(t, int32(2), calls.Load())
}
