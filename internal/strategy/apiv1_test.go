package strategy_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy"
)

func TestPutObjectAbortsOnReadError(t *testing.T) {
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer memCache.Close()

	mux := http.NewServeMux()
	_, err = strategy.NewAPIV1(ctx, strategy.APIV1Config{}, memCache, mux)
	assert.NoError(t, err)

	key := cache.NewKey("abort-test")

	// Create a reader that returns an error after some data.
	body := &failingReader{data: []byte("partial data"), failAfter: 5}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), body)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// The partial data must not be cached.
	nsCache := memCache.Namespace("test")
	_, _, err = nsCache.Open(ctx, key)
	assert.IsError(t, err, os.ErrNotExist)
}

func testAPISetup(t *testing.T) (http.Handler, context.Context) {
	t.Helper()
	handler, ctx, _ := testAPIWithCache(t, strategy.APIV1Config{})
	return handler, ctx
}

func testAPIWithCache(t *testing.T, config strategy.APIV1Config) (http.Handler, context.Context, cache.Cache) {
	t.Helper()
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { memCache.Close() })

	mux := http.NewServeMux()
	_, err = strategy.NewAPIV1(ctx, config, memCache, mux)
	assert.NoError(t, err)
	return mux, ctx, memCache
}

func TestObjectUploadDoesNotStoreCredentials(t *testing.T) {
	handler, ctx, store := testAPIWithCache(t, strategy.APIV1Config{
		Namespaces: []strategy.ObjectNamespaceConfig{{Name: "test", StoredHeaders: []string{"Content-Type", "X-Object-Version"}}},
	})
	key := cache.NewKey("credential-upload")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader("snapshot"))
	req.Header = http.Header{
		"authorization":       {"Bearer test-only-token"},
		"Proxy-Authorization": {"Basic test-only-proxy"},
		"Cookie":              {"session=test-only-cookie"},
		"Set-Cookie":          {"session=test-only-cookie"},
		"Content-Type":        {"application/gzip"},
		"X-Object-Version":    {"1"},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Bearer test-only-token", req.Header["authorization"][0]) //nolint:staticcheck // Verify filtering does not mutate noncanonical input headers.
	body, headers, err := store.Namespace("test").Open(ctx, key)
	assert.NoError(t, err)
	defer body.Close()
	data, err := io.ReadAll(body)
	assert.NoError(t, err)
	assert.Equal(t, "snapshot", string(data))
	assert.Equal(t, "application/gzip", headers.Get("Content-Type"))
	assert.Equal(t, "1", headers.Get("X-Object-Version"))
	assertNoObjectCredentials(t, headers)
}

func assertNoObjectCredentials(t *testing.T, headers http.Header) {
	t.Helper()
	for key := range headers {
		switch http.CanonicalHeaderKey(key) {
		case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie":
			t.Errorf("credential header returned: %s", key)
		}
	}
}

func TestObjectReadsStripLegacyCredentials(t *testing.T) {
	handler, ctx, store := testAPIWithCache(t, strategy.APIV1Config{
		Namespaces: []strategy.ObjectNamespaceConfig{{Name: "test", StoredHeaders: []string{"content-type"}}},
	})
	key := cache.NewKey("legacy-credentials")
	writer, err := store.Namespace("test").Create(ctx, key, http.Header{
		"authorization":       {"Bearer test-only-token"},
		"Proxy-Authorization": {"Basic test-only-proxy"},
		"Cookie":              {"session=test-only-cookie"},
		"Set-Cookie":          {"session=test-only-cookie"},
		"Content-Type":        {"application/gzip"},
		"X-Unlisted":          {"legacy-metadata"},
	}, time.Hour, cache.WithETag("legacy"))
	assert.NoError(t, err)
	_, err = io.WriteString(writer, "snapshot")
	assert.NoError(t, err)
	assert.NoError(t, writer.Close())

	for _, tt := range []struct {
		name, method, header, value, body string
		status                            int
	}{
		{name: "Get", method: http.MethodGet, status: http.StatusOK, body: "snapshot"},
		{name: "Head", method: http.MethodHead, status: http.StatusOK},
		{name: "ConditionalGet", method: http.MethodGet, header: "If-None-Match", value: `"legacy"`, status: http.StatusNotModified},
		{name: "ConditionalHead", method: http.MethodHead, header: "If-None-Match", value: `"legacy"`, status: http.StatusNotModified},
		{name: "Range", method: http.MethodGet, header: "Range", value: "bytes=0-3", status: http.StatusPartialContent, body: "snap"},
		{name: "UnsatisfiableRange", method: http.MethodGet, header: "Range", value: "bytes=99-", status: http.StatusRequestedRangeNotSatisfiable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/v1/object/test/"+key.String(), nil)
			if tt.header != "" {
				req.Header.Set(tt.header, tt.value)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req.WithContext(ctx))
			assert.Equal(t, tt.status, w.Code)
			assert.Equal(t, tt.body, w.Body.String())
			assert.Equal(t, `"legacy"`, w.Header().Get("ETag"))
			assert.Equal(t, "application/gzip", w.Header().Get("Content-Type"))
			assert.Equal(t, "", w.Header().Get("X-Unlisted"))
			assertNoObjectCredentials(t, w.Header())
		})
	}
}

func TestNamespaceStoredHeaders(t *testing.T) {
	handler, ctx, store := testAPIWithCache(t, strategy.APIV1Config{
		Namespaces: []strategy.ObjectNamespaceConfig{
			{Name: "selected", StoredHeaders: []string{"content-type", "X-Object-Version"}},
			{Name: "empty", StoredHeaders: []string{}},
		},
	})
	for _, tt := range []struct{ name, contentType, version, extra string }{
		{name: "selected", contentType: "application/gzip", version: "1"},
		{name: "empty"},
		{name: "unconfigured"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := cache.NewKey(tt.name)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/object/"+tt.name+"/"+key.String(), strings.NewReader("snapshot"))
			req.Header = http.Header{"Content-Type": {"application/gzip"}, "X-Object-Version": {"1"}, "X-Unlisted": {"other"}, "Authorization": {"Bearer dummy"}, "Etag": {`"explicit"`}}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req.WithContext(ctx))
			assert.Equal(t, http.StatusOK, w.Code)
			headers, err := store.Namespace(cache.Namespace(tt.name)).Stat(ctx, key)
			assert.NoError(t, err)
			assert.Equal(t, tt.contentType, headers.Get("Content-Type"))
			assert.Equal(t, tt.version, headers.Get("X-Object-Version"))
			assert.Equal(t, tt.extra, headers.Get("X-Unlisted"))
			assert.Equal(t, `"explicit"`, headers.Get("ETag"))
			assertNoObjectCredentials(t, headers)
		})
	}
}

func TestNamespaceStoredHeadersRejectInvalidNames(t *testing.T) {
	for _, header := range []string{"", "invalid header", "invalid\r\nheader"} {
		t.Run(header, func(t *testing.T) {
			ctx := logging.ContextWithLogger(t.Context(), slog.Default())
			_, err := strategy.NewAPIV1(ctx, strategy.APIV1Config{
				Namespaces: []strategy.ObjectNamespaceConfig{{Name: "test", StoredHeaders: []string{header}}},
			}, nil, http.NewServeMux())
			assert.Error(t, err)
		})
	}
}

func apiPut(ctx context.Context, t *testing.T, handler http.Handler, key cache.Key) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader("test data"))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Stat to get the ETag
	req = httptest.NewRequest(http.MethodHead, "/api/v1/object/test/"+key.String(), nil)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	etag := w.Header().Get("ETag")
	assert.NotZero(t, etag)
	return etag
}

func TestPutObjectDoesNotPersistCredentialHeaders(t *testing.T) {
	handler, ctx, _ := testAPIWithCache(t, strategy.APIV1Config{
		Namespaces: []strategy.ObjectNamespaceConfig{{Name: "test", StoredHeaders: []string{"X-Custom"}}},
	})
	key := cache.NewKey("credential-headers")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader("test data"))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set("Proxy-Authorization", "Basic secret")
	req.Header.Set("X-Custom", "kept")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/object/test/"+key.String(), nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, w.Header().Get("Authorization"))
	assert.Zero(t, w.Header().Get("Cookie"))
	assert.Zero(t, w.Header().Get("Proxy-Authorization"))
	assert.Equal(t, "kept", w.Header().Get("X-Custom"))
}

func TestConditionalGetIfNoneMatch(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("cond-get")
	etag := apiPut(ctx, t, handler, key)

	tests := []struct {
		name           string
		ifNoneMatch    string
		expectedStatus int
	}{
		{name: "Matching", ifNoneMatch: etag, expectedStatus: http.StatusNotModified},
		{name: "NonMatching", ifNoneMatch: `"wrong"`, expectedStatus: http.StatusOK},
		{name: "Wildcard", ifNoneMatch: "*", expectedStatus: http.StatusNotModified},
		{name: "ListMatching", ifNoneMatch: `"a", ` + etag + `, "b"`, expectedStatus: http.StatusNotModified},
		{name: "ListNonMatching", ifNoneMatch: `"a", "b"`, expectedStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/object/test/"+key.String(), nil)
			req = req.WithContext(ctx)
			req.Header.Set("If-None-Match", tt.ifNoneMatch)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedStatus == http.StatusNotModified {
				assert.Equal(t, etag, w.Header().Get("ETag"))
				assert.Equal(t, 0, w.Body.Len())
			}
		})
	}
}

func TestPutObjectWithETag(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("put-explicit-etag")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader("test data"))
	req = req.WithContext(ctx)
	req.Header.Set("ETag", `"caller-etag"`)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodHead, "/api/v1/object/test/"+key.String(), nil)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"caller-etag"`, w.Header().Get("ETag"))
}

func TestPutObjectRejectsInvalidETag(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("put-invalid-etag")

	tests := []struct {
		name string
		etag string
	}{
		{name: "Raw", etag: "raw-etag"},
		{name: "Weak", etag: `W/"weak"`},
		{name: "Space", etag: `"has space"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader("test data"))
			req = req.WithContext(ctx)
			req.Header.Set("ETag", tt.etag)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestConditionalHeadIfNoneMatch(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("cond-head")
	etag := apiPut(ctx, t, handler, key)

	req := httptest.NewRequest(http.MethodHead, "/api/v1/object/test/"+key.String(), nil)
	req = req.WithContext(ctx)
	req.Header.Set("If-None-Match", etag)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.Equal(t, etag, w.Header().Get("ETag"))
}

func TestConditionalGetIfMatch(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("cond-ifmatch")
	etag := apiPut(ctx, t, handler, key)

	tests := []struct {
		name           string
		ifMatch        string
		expectedStatus int
	}{
		{name: "Matching", ifMatch: etag, expectedStatus: http.StatusOK},
		{name: "NonMatching", ifMatch: `"wrong"`, expectedStatus: http.StatusPreconditionFailed},
		{name: "Wildcard", ifMatch: "*", expectedStatus: http.StatusOK},
		{name: "ListMatching", ifMatch: `"a", ` + etag + `, "b"`, expectedStatus: http.StatusOK},
		{name: "ListNonMatching", ifMatch: `"a", "b"`, expectedStatus: http.StatusPreconditionFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/object/test/"+key.String(), nil)
			req = req.WithContext(ctx)
			req.Header.Set("If-Match", tt.ifMatch)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func apiPutBody(ctx context.Context, t *testing.T, handler http.Handler, key cache.Key, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader(body))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodHead, "/api/v1/object/test/"+key.String(), nil)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "bytes", w.Header().Get("Accept-Ranges"))
	return w.Header().Get("ETag")
}

func TestRangeGet(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("range-get")
	apiPutBody(ctx, t, handler, key, "0123456789")

	tests := []struct {
		name         string
		rangeHeader  string
		ifRange      string
		wantStatus   int
		wantBody     string
		wantCotRange string
	}{
		{name: "FirstBytes", rangeHeader: "bytes=0-3", wantStatus: http.StatusPartialContent, wantBody: "0123", wantCotRange: "bytes 0-3/10"},
		{name: "Middle", rangeHeader: "bytes=2-5", wantStatus: http.StatusPartialContent, wantBody: "2345", wantCotRange: "bytes 2-5/10"},
		{name: "OpenEnded", rangeHeader: "bytes=7-", wantStatus: http.StatusPartialContent, wantBody: "789", wantCotRange: "bytes 7-9/10"},
		{name: "Suffix", rangeHeader: "bytes=-3", wantStatus: http.StatusPartialContent, wantBody: "789", wantCotRange: "bytes 7-9/10"},
		{name: "NotSatisfiable", rangeHeader: "bytes=20-30", wantStatus: http.StatusRequestedRangeNotSatisfiable, wantCotRange: "bytes */10"},
		{name: "MultiRangeFallsBackToFull", rangeHeader: "bytes=0-1,4-5", wantStatus: http.StatusOK, wantBody: "0123456789"},
		{name: "NoRange", wantStatus: http.StatusOK, wantBody: "0123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/object/test/"+key.String(), nil)
			req = req.WithContext(ctx)
			if tt.rangeHeader != "" {
				req.Header.Set("Range", tt.rangeHeader)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, "bytes", w.Header().Get("Accept-Ranges"))
			assert.Equal(t, tt.wantCotRange, w.Header().Get("Content-Range"))
			if tt.wantStatus == http.StatusRequestedRangeNotSatisfiable {
				// No body, so the full-size Content-Length must not be advertised.
				assert.Equal(t, "", w.Header().Get("Content-Length"))
			} else {
				assert.Equal(t, tt.wantBody, w.Body.String())
			}
		})
	}
}

func TestRangeGetIfRange(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("range-ifrange")
	etag := apiPutBody(ctx, t, handler, key, "0123456789")

	tests := []struct {
		name       string
		ifRange    string
		wantStatus int
		wantBody   string
	}{
		{name: "Match", ifRange: etag, wantStatus: http.StatusPartialContent, wantBody: "0123"},
		{name: "Mismatch", ifRange: `"stale"`, wantStatus: http.StatusOK, wantBody: "0123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/object/test/"+key.String(), nil)
			req = req.WithContext(ctx)
			req.Header.Set("Range", "bytes=0-3")
			req.Header.Set("If-Range", tt.ifRange)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.wantBody, w.Body.String())
		})
	}
}

// TestRangeStoredContentRangeIgnored guards against a client-supplied
// Content-Range request header being stored and later replayed, which would
// make a plain GET spuriously answer 206.
func TestRangeStoredContentRangeIgnored(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("range-stored-cr")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/object/test/"+key.String(), strings.NewReader("0123456789"))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Range", "bytes 0-4/10")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/object/test/"+key.String(), nil)
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", w.Header().Get("Content-Range"))
	assert.Equal(t, "0123456789", w.Body.String())
}

func TestRangeHeadIgnoresRange(t *testing.T) {
	handler, ctx := testAPISetup(t)
	key := cache.NewKey("range-head")
	apiPutBody(ctx, t, handler, key, "0123456789")

	req := httptest.NewRequest(http.MethodHead, "/api/v1/object/test/"+key.String(), nil)
	req = req.WithContext(ctx)
	req.Header.Set("Range", "bytes=0-3")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "bytes", w.Header().Get("Accept-Ranges"))
	assert.Equal(t, "", w.Header().Get("Content-Range"))
}

// failingReader returns data up to failAfter bytes, then returns an error.
type failingReader struct {
	data      []byte
	failAfter int
	read      int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.read >= r.failAfter {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(p), r.failAfter-r.read, len(r.data)-r.read)
	copy(p[:n], r.data[r.read:r.read+n])
	r.read += n
	if r.read >= r.failAfter {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
