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
	"sync/atomic"
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
	release    <-chan struct{}
	failFirst  *atomic.Bool
	pauseMiss  *atomic.Bool
	missed     chan struct{}
	resumeMiss <-chan struct{}
}

func (d delayedUploadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && r.URL.Query().Get("partNumber") != "" {
		select {
		case <-d.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		if d.failFirst != nil && d.failFirst.Swap(false) {
			return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("<Error><Code>AccessDenied</Code><Message>injected upload failure</Message></Error>")), Request: r}, nil
		}
	}
	resp, err := d.RoundTripper.RoundTrip(r)
	if err == nil && r.Method == http.MethodHead && resp.StatusCode == http.StatusNotFound && d.pauseMiss.Swap(false) {
		d.missed <- struct{}{}
		select {
		case <-d.resumeMiss:
		case <-r.Context().Done():
		}
	}
	return resp, err
}

type cacheFillHarness struct {
	server         *httptest.Server
	store          cache.Cache
	key            cache.Key
	path           string
	body           string
	release        func()
	started        chan struct{}
	canceled       chan struct{}
	finished       chan struct{}
	originRequests atomic.Int32
	pauseMiss      atomic.Bool
	missed         chan struct{}
	resumeMiss     func()
}

func newCacheFillHarness(t *testing.T, bucket, strategyName, scenario string) *cacheFillHarness {
	t.Helper()
	s3clienttest.CleanBucket(t, bucket)
	h := &cacheFillHarness{body: strings.Repeat("artifact", 32768), started: make(chan struct{}, 64), canceled: make(chan struct{}, 64), finished: make(chan struct{}, 64)}
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	release := make(chan struct{})
	releaseUpload := sync.OnceFunc(func() { close(release) })
	resumeMiss := make(chan struct{})
	h.missed = make(chan struct{}, 1)
	h.resumeMiss = sync.OnceFunc(func() { close(resumeMiss) })
	t.Cleanup(h.resumeMiss)
	failFirst := &atomic.Bool{}
	failFirst.Store(scenario == "upload-failure")
	transport, err := minio.DefaultTransport(false)
	assert.NoError(t, err)
	t.Cleanup(transport.CloseIdleConnections)
	client, err := minio.New(s3clienttest.Addr, &minio.Options{
		Creds:           credentials.NewStaticV4(s3clienttest.Username, s3clienttest.Password, ""),
		Region:          "us-east-1",
		TrailingHeaders: true,
		Transport:       delayedUploadTransport{RoundTripper: transport, release: release, failFirst: failFirst, pauseMiss: &h.pauseMiss, missed: h.missed, resumeMiss: resumeMiss},
	})
	assert.NoError(t, err)
	store, err := cache.NewS3(ctx, cache.S3Config{Bucket: bucket, MaxTTL: time.Hour, UploadPartSizeMB: 5}, func() (*minio.Client, error) { return client, nil })
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	body := h.body
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.originRequests.Add(1)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("ETag", testCodeArtifactETag)
		payload := body
		if scenario == "truncated" || scenario == "interrupted" {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.started <- struct{}{}
		defer func() { h.finished <- struct{}{} }()
		context.AfterFunc(r.Context(), func() { h.canceled <- struct{}{} })
		serve.ServeHTTP(w, r.WithContext(logging.ContextWithLogger(r.Context(), logging.FromContext(ctx))))
	}))
	t.Cleanup(server.Close)
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.DisableCompression = true
	server.Client().Transport = clientTransport
	t.Cleanup(clientTransport.CloseIdleConnections)
	t.Cleanup(releaseUpload)

	h.server = server
	h.path = path
	h.key = key
	h.store = store
	if strategyName == "codeartifact" {
		h.store = store.Namespace("codeartifact")
	}
	h.release = releaseUpload
	return h
}

func (h *cacheFillHarness) disconnect(t *testing.T, incomplete bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.server.Listener.Addr().String(), time.Second)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	assert.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", h.path)
	assert.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	if incomplete {
		received := make([]byte, len(h.body)/2)
		_, err = io.ReadFull(response.Body, received)
		assert.NoError(t, err)
		assert.Equal(t, h.body[:len(h.body)/2], string(received))
	} else {
		received, err := io.ReadAll(response.Body)
		assert.NoError(t, err)
		assert.Equal(t, h.body, string(received))
	}
	assert.NoError(t, conn.Close())

	waitCacheFill(t, h.canceled)
}

func waitCacheFill(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal("cache fill event timed out")
	}
}

func (h *cacheFillHarness) assertStored(t *testing.T, incomplete bool) {
	t.Helper()
	cached, _, err := h.store.Open(t.Context(), h.key)
	if incomplete {
		assert.IsError(t, err, os.ErrNotExist)
		return
	}
	assert.NoError(t, err)
	persisted, err := io.ReadAll(cached)
	assert.NoError(t, err)
	assert.NoError(t, cached.Close())
	assert.Equal(t, h.body, string(persisted))
}

func TestCacheFillDisconnect(t *testing.T) {
	bucket := s3clienttest.Start(t)
	for _, strategyName := range []string{"codeartifact", "generic"} {
		for _, scenario := range []string{"complete", "truncated", "interrupted"} {
			t.Run(strategyName+"/"+scenario, func(t *testing.T) {
				h := newCacheFillHarness(t, bucket, strategyName, scenario)
				h.disconnect(t, scenario != "complete")
				h.release()
				waitCacheFill(t, h.finished)
				h.assertStored(t, scenario != "complete")
			})
		}
	}
}
