package strategy //nolint:testpackage // Exercise cached proof rejection and configuration changes through the real handler.

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/zeebo/blake3"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/opa"
)

type releaseOrigin struct {
	mu      sync.Mutex
	objects map[string][]byte
	reads   map[string]int
	offline bool
}

func (o *releaseOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reads[r.Method+" "+r.URL.Path]++
	data, ok := o.objects[r.URL.Path]
	if o.offline {
		http.Error(w, "offline", http.StatusForbidden)
		return
	}
	if !ok {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", `"source"`)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}
func releaseFixture(t *testing.T) (*releaseOrigin, *ReleaseArtifacts, *http.ServeMux, releaseBlob) {
	t.Helper()
	origin := &releaseOrigin{objects: map[string][]byte{}, reads: map[string]int{}}
	server := httptest.NewServer(origin)
	t.Cleanup(server.Close)
	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4("test", "test", ""), Region: "us-east-1", BucketLookup: minio.BucketLookupPath})
	assert.NoError(t, err)
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 8, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	mux := http.NewServeMux()
	s, err := NewReleaseArtifacts(context.Background(), ReleaseArtifactsConfig{Bucket: "artifacts", Artifacts: []string{"example/tool"}, Classes: []string{"releases", "builds", "previews"}}, client, c, mux)
	assert.NoError(t, err)
	sum := sha256.Sum256([]byte("verified payload"))
	b := releaseBlob{artifact: "example/tool", class: "builds", algorithm: "sha256", digest: hex.EncodeToString(sum[:])}
	marker, err := json.Marshal(releaseCompletion{SchemaVersion: 1, Artifact: b.artifact, Class: b.class, Hash: b.algorithm, Digest: b.digest, Size: 16, Ready: true})
	assert.NoError(t, err)
	origin.objects["/artifacts/"+s.root(b)+"complete.json"] = marker
	origin.objects["/artifacts/"+s.root(b)+"payload"] = []byte("verified payload")
	return origin, s, mux, b
}
func releasePath(b releaseBlob) string {
	class := ""
	if b.class != "releases" {
		class = b.class + "/"
	}
	return "/artifacts/" + b.artifact + "/" + class + "blob/" + b.algorithm + "/" + b.digest
}
func releaseRequest(h http.Handler, method, path string, headers http.Header) *httptest.ResponseRecorder {
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	r := httptest.NewRequestWithContext(ctx, method, path, nil)
	if headers != nil {
		r.Header = headers
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestReleaseColdRangeVerifiesFullBodyAndWarmRequestsSurviveOriginOutage(t *testing.T) {
	origin, s, mux, b := releaseFixture(t)
	w := releaseRequest(mux, "GET", releasePath(b), http.Header{"Range": {"bytes=0-7"}})
	assert.Equal(t, 206, w.Code)
	assert.Equal(t, "verified", w.Body.String())
	assert.Equal(t, "", w.Header().Get(releaseVerifiedHeader))
	origin.mu.Lock()
	origin.offline = true
	origin.mu.Unlock()
	for _, tc := range []struct {
		method  string
		headers http.Header
		status  int
		body    string
	}{
		{"GET", nil, 200, "verified payload"},
		{"HEAD", nil, 200, ""},
		{"GET", http.Header{"Range": {"bytes=-7"}}, 206, "payload"},
		{"GET", http.Header{"If-None-Match": {releaseETag(b)}}, 304, ""},
		{"GET", http.Header{"If-Match": {`"other"`}}, 412, ""},
		{"GET", http.Header{"Range": {"bytes=100-200"}}, 416, ""},
	} {
		response := releaseRequest(mux, tc.method, releasePath(b), tc.headers)
		assert.Equal(t, tc.status, response.Code)
		assert.Equal(t, tc.body, response.Body.String())
		assert.Equal(t, "", response.Header().Get(releaseVerifiedHeader))
	}
	origin.mu.Lock()
	defer origin.mu.Unlock()
	assert.Equal(t, 1, origin.reads["GET /artifacts/"+s.root(b)+"payload"])
	assert.Equal(t, 1, origin.reads["GET /artifacts/"+s.root(b)+"complete.json"])
}

func TestReleaseHeadDoesNotFillPayload(t *testing.T) {
	origin, s, mux, b := releaseFixture(t)
	w := releaseRequest(mux, "HEAD", releasePath(b), nil)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "16", w.Header().Get("Content-Length"))
	assert.Equal(t, "", w.Body.String())
	origin.mu.Lock()
	assert.Equal(t, 0, origin.reads["GET /artifacts/"+s.root(b)+"payload"])
	origin.mu.Unlock()
	assert.Equal(t, 200, releaseRequest(mux, "GET", releasePath(b), nil).Code)
	origin.mu.Lock()
	defer origin.mu.Unlock()
	assert.Equal(t, 1, origin.reads["GET /artifacts/"+s.root(b)+"payload"])
}

func TestReleaseInvalidOriginNeverServesOrCachesBytes(t *testing.T) {
	for _, change := range []string{"hash", "short", "long", "not-ready", "wrong-class", "schema", "duplicate", "unknown", "missing", "oversize"} {
		t.Run(change, func(t *testing.T) {
			origin, s, mux, b := releaseFixture(t)
			payload := "/artifacts/" + s.root(b) + "payload"
			completion := "/artifacts/" + s.root(b) + "complete.json"
			goodPayload := origin.objects[payload]
			goodCompletion := origin.objects[completion]
			switch change {
			case "hash":
				origin.objects[payload] = []byte("corrupted bytes!")
			case "short":
				origin.objects[payload] = []byte("short")
			case "long":
				origin.objects[payload] = []byte("verified payload extra")
			case "not-ready":
				origin.objects[completion] = []byte(strings.ReplaceAll(string(goodCompletion), `"ready":true`, `"ready":false`))
			case "wrong-class":
				origin.objects[completion] = []byte(strings.ReplaceAll(string(goodCompletion), `"builds"`, `"releases"`))
			case "schema":
				origin.objects[completion] = []byte(strings.ReplaceAll(string(goodCompletion), `"schema_version":1`, `"schema_version":2`))
			case "duplicate":
				origin.objects[completion] = []byte(strings.ReplaceAll(string(goodCompletion), `"ready":true`, `"ready":false,"ready":true`))
			case "unknown":
				origin.objects[completion] = []byte(strings.ReplaceAll(string(goodCompletion), `"ready":true`, `"ready":true,"extra":0`))
			case "missing":
				delete(origin.objects, completion)
			case "oversize":
				s.config.MaxBlobBytes = 8
			}
			response := releaseRequest(mux, "GET", releasePath(b), http.Header{"Range": {"bytes=0-1"}})
			assert.True(t, response.Code >= 400)
			assert.NotContains(t, response.Body.String(), "verified")
			origin.mu.Lock()
			origin.objects[payload] = goodPayload
			origin.objects[completion] = goodCompletion
			origin.mu.Unlock()
			s.config.MaxBlobBytes = 1024
			response = releaseRequest(mux, "GET", releasePath(b), nil)
			assert.Equal(t, 200, response.Code)
			assert.Equal(t, "verified payload", response.Body.String())
		})
	}
}

func TestReleaseAdmissionPrecedesWarmCache(t *testing.T) {
	_, s, mux, b := releaseFixture(t)
	assert.Equal(t, 200, releaseRequest(mux, "GET", releasePath(b), nil).Code)
	s.config.Classes = []string{"releases"}
	assert.Equal(t, 404, releaseRequest(mux, "GET", releasePath(b), nil).Code)
	s.config.Classes = []string{"builds"}
	guarded, err := opa.Middleware(context.Background(), opa.Config{Policy: `package cachew.authz
 default allow := false
 allow if input.headers["x-test-admission"] == "allow"`}, mux)
	assert.NoError(t, err)
	assert.Equal(t, 403, releaseRequest(guarded, "GET", releasePath(b), nil).Code)
	assert.Equal(t, 200, releaseRequest(guarded, "GET", releasePath(b), http.Header{"X-Test-Admission": {"allow"}}).Code)
	for _, path := range []string{releasePath(b) + "?source=other", strings.Replace(releasePath(b), "example/tool", "other/tool", 1), strings.Replace(releasePath(b), "sha256", "md5", 1), strings.Replace(releasePath(b), "example", "%65xample", 1)} {
		assert.Equal(t, 404, releaseRequest(mux, "GET", path, nil).Code)
	}
	assert.Equal(t, 405, releaseRequest(mux, "POST", releasePath(b), nil).Code)
}

func TestReleaseGenericCacheEntryCannotAuthorizeBlob(t *testing.T) {
	origin, s, mux, b := releaseFixture(t)
	writer, err := s.cache.Create(context.Background(), s.key(b), http.Header{"Content-Length": {"9"}}, time.Hour, cache.WithETag(b.algorithm+":"+b.digest))
	assert.NoError(t, err)
	_, err = writer.Write([]byte("untrusted"))
	assert.NoError(t, err)
	assert.NoError(t, writer.Close())
	response := releaseRequest(mux, "GET", releasePath(b), nil)
	assert.Equal(t, 200, response.Code)
	assert.Equal(t, "verified payload", response.Body.String())
	origin.mu.Lock()
	defer origin.mu.Unlock()
	assert.Equal(t, 1, origin.reads["GET /artifacts/"+s.root(b)+"payload"])
}

func TestReleaseCacheSeparatesPublicationClassAndSource(t *testing.T) {
	origin, s, mux, b := releaseFixture(t)
	assert.Equal(t, 200, releaseRequest(mux, "GET", releasePath(b), nil).Code)
	public := b
	public.class = "releases"
	assert.Equal(t, 404, releaseRequest(mux, "GET", releasePath(public), nil).Code)
	s.config.Bucket = "different-bucket"
	response := releaseRequest(mux, "GET", releasePath(b), nil)
	assert.Equal(t, 404, response.Code)
	origin.mu.Lock()
	defer origin.mu.Unlock()
	assert.Equal(t, 1, origin.reads["GET /different-bucket/"+s.root(b)+"complete.json"])
}

func TestReleaseFillCapacityRejectsBeforeOriginRead(t *testing.T) {
	origin, s, mux, b := releaseFixture(t)
	for range cap(s.fills) {
		s.fills <- struct{}{}
	}
	response := releaseRequest(mux, "GET", releasePath(b), nil)
	assert.Equal(t, 503, response.Code)
	assert.Equal(t, 0, len(origin.reads))
	<-s.fills
	assert.Equal(t, 200, releaseRequest(mux, "GET", releasePath(b), nil).Code)
}

func TestReleaseDeclaredHashAlgorithms(t *testing.T) {
	for _, algorithm := range []string{"sha512", "blake3"} {
		t.Run(algorithm, func(t *testing.T) {
			origin, s, mux, b := releaseFixture(t)
			payload := []byte("verified payload")
			b.algorithm = algorithm
			if algorithm == "sha512" {
				sum := sha512.Sum512(payload)
				b.digest = hex.EncodeToString(sum[:])
			} else {
				sum := blake3.Sum256(payload)
				b.digest = hex.EncodeToString(sum[:])
			}
			marker, err := json.Marshal(releaseCompletion{SchemaVersion: 1, Artifact: b.artifact, Class: b.class, Hash: b.algorithm, Digest: b.digest, Size: int64(len(payload)), Ready: true})
			assert.NoError(t, err)
			origin.objects["/artifacts/"+s.root(b)+"complete.json"] = marker
			origin.objects["/artifacts/"+s.root(b)+"payload"] = payload
			response := releaseRequest(mux, "GET", releasePath(b), nil)
			assert.Equal(t, 200, response.Code)
			assert.Equal(t, string(payload), response.Body.String())
		})
	}
}
