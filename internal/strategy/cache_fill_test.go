package strategy //nolint:testpackage // Reuse the CodeArtifact origin and token fixtures.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/s3client/s3clienttest"
	"github.com/block/cachew/internal/strategy/handler"
)

type delayedUploadTransport struct {
	http.RoundTripper
	release <-chan struct{}
}

func (d delayedUploadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && r.URL.Query().Get("partNumber") != "" {
		select {
		case <-d.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return d.RoundTripper.RoundTrip(r)
}

func TestCacheFillDisconnect(t *testing.T) {
	bucket := s3clienttest.Start(t)
	for _, strategyName := range []string{"codeartifact", "generic"} {
		for _, scenario := range []string{"complete", "truncated", "interrupted"} {
			t.Run(strategyName+"/"+scenario, func(t *testing.T) {
				incomplete := scenario != "complete"
				s3clienttest.CleanBucket(t, bucket)
				_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
				release := make(chan struct{})
				releaseUpload := sync.OnceFunc(func() { close(release) })
				transport, err := minio.DefaultTransport(false)
				assert.NoError(t, err)
				t.Cleanup(transport.CloseIdleConnections)
				client, err := minio.New(s3clienttest.Addr, &minio.Options{
					Creds:           credentials.NewStaticV4(s3clienttest.Username, s3clienttest.Password, ""),
					Region:          "us-east-1",
					TrailingHeaders: true,
					Transport:       delayedUploadTransport{RoundTripper: transport, release: release},
				})
				assert.NoError(t, err)
				store, err := cache.NewS3(ctx, cache.S3Config{Bucket: bucket, MaxTTL: time.Hour, UploadPartSizeMB: 5}, func() (*minio.Client, error) { return client, nil })
				assert.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
				body := strings.Repeat("artifact", 32768)
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
					w.Header().Set("ETag", testCodeArtifactETag)
					payload := body
					if incomplete {
						payload = body[:len(body)/2]
					}
					_, _ = io.WriteString(w, payload)
					if scenario == "interrupted" {
						_ = http.NewResponseController(w).Flush()
						<-r.Context().Done()
					}
				}))
				t.Cleanup(origin.Close)
				path := "/npm/repository/artifact/-/artifact-1.0.0.tgz"
				mux := http.NewServeMux()
				var serve http.Handler = mux
				var key cache.Key
				if strategyName == "codeartifact" {
					tokens := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
					strategy, err := newCodeArtifact(ctx, testCodeArtifactConfig(origin.URL), mux, tokens.tokenManager(time.Now), store, true)
					assert.NoError(t, err)
					path = codeArtifactPath(origin, path)
					key = strategy.cacheKey(httptest.NewRequest(http.MethodGet, path, nil))
				} else {
					key = cache.NewKey("artifact")
					serve = handler.New(origin.Client(), store).
						CacheKey(func(*http.Request) string { return "artifact" }).
						Transform(func(r *http.Request) (*http.Request, error) {
							return http.NewRequestWithContext(r.Context(), http.MethodGet, origin.URL+path, nil)
						})
				}
				requestCanceled := make(chan struct{})
				finished := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(finished)
					context.AfterFunc(r.Context(), func() { close(requestCanceled) })
					serve.ServeHTTP(w, r.WithContext(logging.ContextWithLogger(r.Context(), logging.FromContext(ctx))))
				}))
				t.Cleanup(server.Close)
				t.Cleanup(releaseUpload)
				conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
				assert.NoError(t, err)
				t.Cleanup(func() { _ = conn.Close() })
				assert.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
				_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", path)
				assert.NoError(t, err)
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
				if incomplete {
					received := make([]byte, len(body)/2)
					_, err = io.ReadFull(response.Body, received)
					assert.NoError(t, err)
					assert.Equal(t, body[:len(body)/2], string(received))
				} else {
					received, err := io.ReadAll(response.Body)
					assert.NoError(t, err)
					assert.Equal(t, body, string(received))
				}
				assert.NoError(t, conn.Close())
				select {
				case <-requestCanceled:
				case <-time.After(5 * time.Second):
					t.Fatal("request not canceled after disconnect")
				}
				releaseUpload()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Fatal("cache fill did not finish")
				}
				readStore := cache.Cache(store)
				if strategyName == "codeartifact" {
					readStore = store.Namespace("codeartifact")
				}
				cached, _, err := readStore.Open(ctx, key)
				if incomplete {
					assert.IsError(t, err, os.ErrNotExist)
					return
				}
				assert.NoError(t, err)
				persisted, err := io.ReadAll(cached)
				assert.NoError(t, err)
				assert.NoError(t, cached.Close())
				assert.Equal(t, body, string(persisted))
			})
		}
	}
}
