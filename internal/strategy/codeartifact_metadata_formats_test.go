package strategy //nolint:testpackage // Verify protocol admission and complete responses at the HTTP boundary.

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"
)

func allMetadataTestConfig() MetadataCacheConfig {
	cfg := metadataCacheTestConfig()
	cfg.Repositories = []string{"*"}
	cfg.Formats = []string{"npm", "pypi", "cargo", "swift"}
	return cfg
}

func TestMetadataFormatsWarmExpiryAndRefresh(t *testing.T) {
	for _, tt := range []struct{ name, path, media, body string }{
		{"npm", "/npm/other/react", "application/json", `{"name":"react"}`},
		{"pypi HTML", "/pypi/python/simple/pip/", "text/html", `<a href="../../files/pip.whl#sha256=abc" data-yanked="reason" data-requires-python=">=3">pip</a>`},
		{"pypi JSON", "/pypi/python/simple/pip/", "application/vnd.pypi.simple.v1+json", `{"files":[{"filename":"pip.whl","hashes":{"sha256":"abc"},"yanked":true}],"meta":{"api-version":"1.1"}}`},
		{"cargo config", "/cargo/rust/config.json", "application/json", `{"auth-required":false,"dl":"https://example.org/crates/{crate}/{version}"}`},
		{"cargo index", "/cargo/rust/se/rd/serde", "application/octet-stream", "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":true}\n{\"name\":\"serde\",\"vers\":\"2.0.0\",\"yanked\":false}\n"},
		{"swift releases", "/swift/ios/scope/package", "application/json", `{"releases":{"1.0.0":{}}}`},
		{"swift version JSON", "/swift/ios/scope/package/1.0.0.json", "application/vnd.swift.registry.v1+json", `{"id":"scope.package","version":"1.0.0"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			var clock atomic.Int64
			start := time.Date(2026, 9, 18, 22, 0, 0, 0, time.UTC)
			clock.Store(start.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()) }
			mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tt.media)
				w.Header().Set("Content-Version", "1")
				w.Header().Set("Date", now().UTC().Format(http.TimeFormat))
				_, _ = io.WriteString(w, tt.body)
			}), allMetadataTestConfig())
			strategy.metadata.now = now
			request := func(directive string) {
				r := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, tt.path), nil)
				r.Header.Set("Cache-Control", directive)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, tt.body, w.Body.String())
				assert.Equal(t, "1", w.Header().Get("Content-Version"))
				assert.Equal(t, "private, no-cache", w.Header().Get("Cache-Control"))
			}
			request("")
			request("")
			assert.Equal(t, int32(1), calls.Load())
			clock.Store(start.Add(30 * time.Second).UnixNano())
			request("")
			assert.Equal(t, int32(2), calls.Load())
			request("no-cache")
			assert.Equal(t, int32(3), calls.Load())
		})
	}
}

func TestMetadataPassthroughEncodingAndAcceptVariants(t *testing.T) {
	var calls atomic.Int32
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		w.Header().Set("Vary", "Accept, Accept-Encoding")
		body := fmt.Appendf(nil, `{"accept":%q}`, r.Header.Get("Accept"))
		if r.Header.Get("Accept-Encoding") == "deflate" {
			var compressed bytes.Buffer
			writer := zlib.NewWriter(&compressed)
			_, _ = writer.Write(body)
			_ = writer.Close()
			body = compressed.Bytes()
			w.Header().Set("Content-Encoding", "deflate")
		}
		_, _ = w.Write(body)
	}), allMetadataTestConfig())
	for _, accept := range []string{"application/vnd.pypi.simple.v1+json", "*/*"} {
		for _, encoding := range []string{"identity", "deflate"} {
			for range 2 {
				req := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/pypi/python/simple/pip/"), nil)
				req.Header.Set("Accept", accept)
				req.Header.Set("Accept-Encoding", encoding)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code)
				body := w.Body.Bytes()
				if encoding == "deflate" {
					reader, err := zlib.NewReader(w.Body)
					assert.NoError(t, err)
					body, err = io.ReadAll(reader)
					assert.NoError(t, err)
					assert.NoError(t, reader.Close())
					assert.Equal(t, "deflate", w.Header().Get("Content-Encoding"))
				} else {
					assert.Equal(t, "", w.Header().Get("Content-Encoding"))
				}
				assert.Equal(t, fmt.Sprintf(`{"accept":%q}`, accept), string(body))
			}
		}
	}
	assert.Equal(t, int32(4), calls.Load())
}

func TestMetadataRejectsTruncatedStreams(t *testing.T) {
	for _, path := range []string{"/pypi/python/simple/pip/", "/cargo/rust/se/rd/serde"} {
		t.Run(path, func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				media := "text/html"
				if strings.HasPrefix(path, "/cargo/") {
					media = "application/octet-stream"
				}
				w.Header().Set("Content-Type", media)
				if calls.Add(1) == 1 {
					w.Header().Set("Content-Length", "100")
				}
				_, _ = io.WriteString(w, "complete")
			}), allMetadataTestConfig())
			for _, status := range []int{http.StatusBadGateway, http.StatusOK, http.StatusOK} {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, path), nil))
				assert.Equal(t, status, w.Code)
				if status == http.StatusOK {
					assert.Equal(t, "complete", w.Body.String())
				} else {
					assert.Equal(t, "incomplete metadata response\n", w.Body.String())
				}
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestMetadataAdmissionExcludesOtherResources(t *testing.T) {
	for _, tt := range []struct{ path, media, body string }{
		{"/npm/repo/react/-/react.tgz", "application/octet-stream", "artifact\x00"},
		{"/pypi/repo/packages/pip.whl", "application/octet-stream", "artifact\x00"},
		{"/pypi/repo/simple/pip/pip.whl.metadata", "text/plain", "Name: pip"},
		{"/cargo/repo/crates/serde/1.0.0", "application/octet-stream", "artifact\x00"},
		{"/swift/repo/scope/package/1.0.0", "application/zip", "artifact\x00"},
		{"/swift/repo/scope/package/1.0.0.zip", "application/zip", "artifact\x00"},
		{"/swift/repo/login", "application/json", `{}`},
		{"/nuget/repo/v3/index.json", "application/json", `{}`},
		{"/maven/repo/org/pkg/maven-metadata.xml", "application/xml", "<metadata/>"},
		{"/pypi/repo/simple/pip/?x=1", "text/html", "index"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			var calls atomic.Int32
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tt.media)
				_, _ = io.WriteString(w, tt.body)
			}), allMetadataTestConfig())
			for range 2 {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, tt.path), nil))
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, tt.body, w.Body.String())
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestMetadataSpoolsPassthroughAndCleansUp(t *testing.T) {
	for _, budget := range []int{1 << 20, 4 << 20} {
		t.Run(strconv.Itoa(budget), func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			const bodySize = 2 << 20
			var calls atomic.Int32
			config := allMetadataTestConfig()
			config.MaxBytes = budget
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, strings.Repeat("x", bodySize))
			}), config)
			for range 2 {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/pypi/python/simple/pip/"), nil))
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, strings.Repeat("x", bodySize), w.Body.String())
				files, err := os.ReadDir(directory)
				assert.NoError(t, err)
				assert.Equal(t, 0, len(files))
			}
			want := int32(2)
			if budget > bodySize {
				want = 1
			}
			assert.Equal(t, want, calls.Load())
		})
	}
}

func TestMetadataWildcardHCLAndFormatSelection(t *testing.T) {
	var config struct {
		Cache MetadataCacheConfig `hcl:"metadata-cache,block"`
	}
	assert.NoError(t, hcl.Unmarshal([]byte(`metadata-cache {
 repositories = ["*"]
 formats = ["pypi"]
 ttl = "30s"
 max-bytes = 67108864
 max-concurrent = 4
 }`), &config))
	assert.NoError(t, validateMetadataCache(&config.Cache))
	var calls atomic.Int32
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasPrefix(r.URL.Path, "/npm/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "index")
	}), config.Cache)
	for _, path := range []string{"/pypi/first/simple/pip/", "/pypi/second/simple/pip/", "/npm/first/react"} {
		before := calls.Load()
		for range 2 {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, path), nil))
			assert.Equal(t, http.StatusOK, w.Code)
		}
		want := int32(1)
		if strings.HasPrefix(path, "/npm/") {
			want = 2
		}
		assert.Equal(t, before+want, calls.Load())
	}
}

func TestMetadataCanceledWaiterSpoolCleanup(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	entered := make(chan struct{})
	release := make(chan struct{})
	mux, origin, strategy := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, strings.Repeat("x", 2<<20))
	}), allMetadataTestConfig())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/pypi/python/simple/pip/"), nil).WithContext(ctx))
	}()
	<-entered
	strategy.metadata.mu.Lock()
	var active *metadataFlight
	for _, flight := range strategy.metadata.flights {
		active = flight
	}
	strategy.metadata.mu.Unlock()
	assert.NotZero(t, active)
	cancel()
	<-done
	close(release)
	<-active.done
	strategy.metadata.mu.Lock()
	assert.Equal(t, 0, len(strategy.metadata.flights))
	strategy.metadata.mu.Unlock()
	files, err := os.ReadDir(directory)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(files))
}

func TestMetadataTruncatedAuthoritativeResponseInvalidatesVariants(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone, http.StatusUnavailableForLegalReasons} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var removed atomic.Bool
			mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if removed.Load() {
					w.Header().Set("Content-Length", "100")
					w.WriteHeader(status)
				}
				_, _ = io.WriteString(w, "index")
			}), allMetadataTestConfig())
			request := func(accept string) int {
				r := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/pypi/python/simple/pip/"), nil)
				r.Header.Set("Accept", accept)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				return w.Code
			}
			assert.Equal(t, http.StatusOK, request("text/html"))
			removed.Store(true)
			assert.Equal(t, http.StatusBadGateway, request("*/*"))
			assert.Equal(t, http.StatusBadGateway, request("text/html"))
		})
	}
}

type metadataBlockedFailWriter struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
}

func (w *metadataBlockedFailWriter) Header() http.Header { return w.header }
func (w *metadataBlockedFailWriter) WriteHeader(int)     {}
func (w *metadataBlockedFailWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.release
	return 0, io.ErrClosedPipe
}

func TestMetadataSpoolLastWriterFailurePreservesOtherReaders(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	entered := make(chan struct{})
	release := make(chan struct{})
	body := strings.Repeat("abcdefgh", 1<<18)
	mux, origin, _ := newMetadataCacheProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	}), allMetadataTestConfig())
	path := codeArtifactPath(origin, "/pypi/python/simple/pip/")
	failed := &metadataBlockedFailWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	ownerDone := make(chan struct{})
	go func() { defer close(ownerDone); mux.ServeHTTP(failed, httptest.NewRequest(http.MethodGet, path, nil)) }()
	<-entered
	joined := make(chan struct{}, 1)
	healthy := httptest.NewRecorder()
	healthyDone := make(chan struct{})
	go func() {
		defer close(healthyDone)
		ctx := &metadataWaitContext{Context: t.Context(), joined: joined}
		mux.ServeHTTP(healthy, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
	}()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("follower did not join")
	}
	close(release)
	<-failed.entered
	<-healthyDone
	assert.Equal(t, http.StatusOK, healthy.Code)
	assert.Equal(t, body, healthy.Body.String())
	files, err := os.ReadDir(directory)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(files))
	close(failed.release)
	<-ownerDone
	files, err = os.ReadDir(directory)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(files))
}
