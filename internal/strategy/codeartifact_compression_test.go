package strategy //nolint:testpackage // Exercise the authenticated proxy with a local origin.

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestCodeArtifactMetadataCompression(t *testing.T) {
	for _, path := range []string{"/npm/repository/react", "/npm/repository/@sanity%2Fvision"} {
		t.Run(path, func(t *testing.T) {
			var originURL string
			origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "gzip", r.Header.Get("Accept-Encoding"))
				w.Header().Set("Content-Type", "application/vnd.npm.install-v1+json")
				w.Header().Set("Vary", "Accept")
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("ETag", testCodeArtifactETag)
				w.Write(codeArtifactGzip(t, []byte(`{"tarball":"`+originURL+`/npm/repository/pkg/-/pkg.tgz","padding":"`+strings.Repeat("x", 8192)+`"}`)))
			})
			mux, server, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
			originURL = server.URL
			for _, test := range []struct {
				accept string
				gzip   bool
			}{
				{accept: "gzip", gzip: true},
				{accept: "br, gzip;q=0.8", gzip: true},
				{accept: "*;q=0.5", gzip: true},
				{accept: "gzip;q=0, *;q=1"},
				{accept: "gzip;q=0.2, identity;q=1"},
				{accept: "gzip;q=bogus"},
				{accept: "gzip;q=NaN"},
				{accept: "br"},
				{},
			} {
				t.Run(test.accept, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, codeArtifactPath(server, path), nil).WithContext(ctx)
					req.Header.Set("Accept-Encoding", test.accept)
					w := httptest.NewRecorder()
					mux.ServeHTTP(w, req)
					assert.Equal(t, http.StatusOK, w.Code)
					assert.Equal(t, strconv.Itoa(w.Body.Len()), w.Header().Get("Content-Length"))
					assert.Equal(t, "", w.Header().Get("ETag"))
					assert.Equal(t, "Accept, Accept-Encoding", strings.Join(w.Header().Values("Vary"), ", "))
					body := w.Body.Bytes()
					if test.gzip {
						assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
						assert.True(t, len(body) < 1024, "compress the metadata, not just its headers")
						body = codeArtifactGunzip(t, body)
					} else {
						assert.Equal(t, "", w.Header().Get("Content-Encoding"))
					}
					proxy := "https://cachew.example.com/" + server.Listener.Addr().String()
					assertJSONEqual(t, `{"tarball":"`+proxy+`/npm/repository/pkg/-/pkg.tgz","padding":"`+strings.Repeat("x", 8192)+`"}`, string(body))
				})
			}
		})
	}
}

func TestCodeArtifactRejectsInvalidCompressedMetadata(t *testing.T) {
	valid := codeArtifactGzip(t, []byte(`{"name":"package"}`))
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-8] ^= 1
	for _, test := range []struct {
		name     string
		encoding string
		body     []byte
	}{
		{name: "invalid gzip", encoding: "gzip", body: []byte("invalid")},
		{name: "truncated gzip", encoding: "gzip", body: valid[:len(valid)-4]},
		{name: "checksum mismatch", encoding: "gzip", body: corrupt},
		{name: "unsupported encoding", encoding: "br", body: []byte(`{"name":"package"}`)},
		{name: "decompressed size limit", encoding: "gzip", body: codeArtifactGzip(t, []byte(`"`+strings.Repeat("x", maxCodeArtifactMetadataBytes)+`"`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", test.encoding)
				w.Write(test.body)
			})
			mux, server, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(server, "/npm/repository/package"), nil).WithContext(ctx))
			assert.Equal(t, http.StatusBadGateway, w.Code)
			assert.Equal(t, "", w.Header().Get("Content-Encoding"))
		})
	}
}

func TestCodeArtifactCompressedMetadataHEAD(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", "123")
		w.Header().Set("Vary", "Accept-Encoding, Accept")
	})
	mux, server, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	req := httptest.NewRequest(http.MethodHead, codeArtifactPath(server, "/npm/repository/package"), nil).WithContext(ctx)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
	assert.Equal(t, "", w.Header().Get("Content-Length"))
	assert.Equal(t, "Accept-Encoding, Accept", strings.Join(w.Header().Values("Vary"), ", "))
	assert.Equal(t, 0, w.Body.Len())
}

func TestCodeArtifactMetadataCompressionCacheVariants(t *testing.T) {
	var calls atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept")
		w.Write(codeArtifactGzip(t, []byte(`{"name":"package"}`)))
	})
	mux, server, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	for range 2 {
		for _, encoding := range []string{"gzip", "identity"} {
			req := httptest.NewRequest(http.MethodGet, codeArtifactPath(server, "/npm/repository/package"), nil).WithContext(ctx)
			req.Header.Set("Accept-Encoding", encoding)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			body := w.Body.Bytes()
			if encoding == "gzip" {
				assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
				body = codeArtifactGunzip(t, body)
			} else {
				assert.Equal(t, "", w.Header().Get("Content-Encoding"))
			}
			assert.Equal(t, `{"name":"package"}`, string(body))
		}
	}
	assert.Equal(t, int32(2), calls.Load(), "cache each encoding independently")
}

func TestCodeArtifactDecodesCompressedMetadataError(t *testing.T) {
	const message = "package not found"
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", testCodeArtifactETag)
		w.WriteHeader(http.StatusNotFound)
		w.Write(codeArtifactGzip(t, []byte(message)))
	})
	mux, server, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(server, "/npm/repository/missing"), nil).WithContext(ctx))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "", w.Header().Get("Content-Encoding"))
	assert.Equal(t, "", w.Header().Get("ETag"))
	assert.Equal(t, message, w.Body.String())
}

func codeArtifactGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write(body)
	assert.NoError(t, err)
	assert.NoError(t, writer.Close())
	return buffer.Bytes()
}

func codeArtifactGunzip(t *testing.T, body []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(body))
	assert.NoError(t, err)
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	assert.NoError(t, err)
	return decoded
}
