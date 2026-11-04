package strategy //nolint:testpackage // Exercise the real SDK and cache backends against local origins.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/minio/minio-go/v7"
	miniocredentials "github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/s3client/s3clienttest"
)

func newRangeTestStrategy(ctx context.Context, t *testing.T, origin string, backend cache.Cache) (*CodeArtifact, http.Handler) {
	t.Helper()
	config := testCodeArtifactConfig(origin)
	config.AssetAPI = true
	config.ProxyBaseURL = ""
	config.ImmutableFallbackTTL = time.Hour
	config.Aliases = []CodeArtifactAliasConfig{{Pattern: "/downloads/{version}/{asset}", Path: "/maven/packages/org/example/tool/{version}/{asset}"}}
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, config, mux, nil, backend, true)
	assert.NoError(t, err)
	strategy.assets = &codeArtifactAssetOrigin{
		domain: "example", owner: "123456789012",
		client: awscodeartifact.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("fixture", "fixture", "")}, func(o *awscodeartifact.Options) { o.BaseEndpoint = aws.String(origin); o.RetryMaxAttempts = 1 }),
	}
	return strategy, mux
}

func TestAssetRangeS3(t *testing.T) {
	for _, scenario := range []string{"tiered", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
			bucket := s3clienttest.Start(t)
			var origins, ranges, heads atomic.Int32
			var replace func()
			var replacing atomic.Bool
			transport, err := minio.DefaultTransport(false)
			assert.NoError(t, err)
			client, err := minio.New(s3clienttest.Addr, &minio.Options{
				Creds: miniocredentials.NewStaticV4(s3clienttest.Username, s3clienttest.Password, ""), Secure: false, TrailingHeaders: true,
				Transport: codeArtifactRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method == http.MethodGet && r.Header.Get("Range") != "" {
						ranges.Add(1)
					}
					if r.Method == http.MethodHead && replacing.Load() && heads.Add(1) == 2 {
						replacing.Store(false)
						replace()
					}
					return transport.RoundTrip(r)
				}),
			})
			assert.NoError(t, err)
			s3, err := cache.NewS3(ctx, cache.S3Config{Bucket: bucket, MaxTTL: time.Hour, UploadPartSizeMB: 16, UploadConcurrency: 1}, func() (*minio.Client, error) { return client, nil })
			assert.NoError(t, err)
			var backend cache.Cache = s3
			var memory *cache.Memory
			if scenario == "tiered" {
				memory, err = cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
				assert.NoError(t, err)
				backend = cache.MaybeNewTiered(ctx, []cache.Cache{memory, s3}, metadatadb.New(ctx, metadatadb.NewMemoryBackend()))
			}
			defer backend.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				origins.Add(1)
				w.Header().Set("Content-Length", "7")
				w.Header().Set("X-Packageversionrevision", "revision-1")
				_, _ = io.WriteString(w, "archive")
			}))
			defer origin.Close()
			strategy, handler := newRangeTestStrategy(ctx, t, origin.URL, backend)
			request := httptest.NewRequest(http.MethodGet, "/downloads/1/tool.tar", nil).WithContext(ctx)
			full := httptest.NewRecorder()
			handler.ServeHTTP(full, request)
			assert.Equal(t, "archive", full.Body.String())
			keyRequest := httptest.NewRequest(http.MethodGet, strategy.prefix+"/maven/packages/org/example/tool/1/tool.tar", nil)
			key := strategy.cacheKey(keyRequest)
			if memory != nil {
				assert.NoError(t, memory.Namespace("codeartifact-assets").Invalidate(ctx, key))
			}
			if scenario == "replacement" {
				headers, statErr := strategy.cache.Stat(ctx, key)
				assert.NoError(t, statErr)
				replace = func() {
					assert.NoError(t, cache.WriteFunc(ctx, strategy.cache, key, headers, time.Hour, func(w io.Writer) error {
						_, writeErr := io.WriteString(w, "changed")
						return writeErr
					}, cache.WithETag("replacement")))
				}
				replacing.Store(true)
			}
			before := ranges.Load()
			request.Header.Set("Range", "bytes=2-4")
			partial := httptest.NewRecorder()
			handler.ServeHTTP(partial, request)
			assert.Equal(t, 206, partial.Code)
			assert.Equal(t, "chi", partial.Body.String())
			assert.Equal(t, "bytes 2-4/7", partial.Header().Get("Content-Range"))
			if scenario == "tiered" {
				assert.True(t, ranges.Load() > before)
				assert.Equal(t, int32(1), origins.Load())
			} else {
				assert.False(t, replacing.Load())
				assert.Equal(t, int32(2), origins.Load())
			}
		})
	}
}

func TestCodeArtifactRangeFlushesBeforePrefix(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "7")
		assert.NoError(t, http.NewResponseController(w).Flush())
		select {
		case <-release:
			_, _ = io.WriteString(w, "archive")
		case <-r.Context().Done():
		}
	}))
	defer origin.Close()
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer memory.Close()
	_, handler := newRangeTestStrategy(ctx, t, origin.URL, memory)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(logging.ContextWithLogger(r.Context(), logging.FromContext(ctx))))
	}))
	defer server.Close()
	defer close(release)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/downloads/1/tool.tar", nil)
	assert.NoError(t, err)
	request.Header.Set("Range", "bytes=2-")
	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Do(request)
	assert.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, 206, response.StatusCode)
	release <- struct{}{}
	body, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	assert.Equal(t, "chive", string(body))
}
