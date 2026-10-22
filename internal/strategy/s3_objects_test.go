package strategy //nolint:testpackage // White-box coverage is required for credential and origin injection.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/handler"
)

const (
	testS3Bucket = "example-artifacts"
	testS3Region = "us-east-1"
	testS3Owner  = "111122223333"
	testS3Host   = testS3Bucket + ".s3." + testS3Region + ".amazonaws.com"
)

func testS3Now() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }

func testS3Config() S3ObjectsConfig {
	return s3ObjectsConfigWithDefaults(S3ObjectsConfig{
		Bucket:        testS3Bucket,
		Region:        testS3Region,
		ExpectedOwner: testS3Owner,
		Prefixes:      []string{"bazel/archives/"},
	})
}

type s3TestOrigin struct {
	server   *httptest.Server
	requests atomic.Int32
	last     atomic.Pointer[http.Request]
}

func newS3TestOrigin(t *testing.T, h http.HandlerFunc) *s3TestOrigin {
	t.Helper()
	o := &s3TestOrigin{}
	o.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.requests.Add(1)
		o.last.Store(r.Clone(context.Background()))
		h(w, r)
	}))
	t.Cleanup(o.server.Close)
	return o
}

func newTestS3Objects(t *testing.T, config S3ObjectsConfig, origin *s3TestOrigin, creds aws.CredentialsProvider) http.Handler {
	t.Helper()
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = memCache.Close() })
	originURL, err := url.Parse(origin.server.URL)
	assert.NoError(t, err)
	if creds == nil {
		creds = credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")
	}
	mux := http.NewServeMux()
	_, err = newS3Objects(config, memCache, mux, creds, originURL, testS3Now)
	assert.NoError(t, err)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func serveS3(t *testing.T, mux http.Handler, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// resign recomputes the SigV4 signature from the request as received on the
// wire, which fails if the signed canonical URI or headers differ from what was sent.
func resign(t *testing.T, received *http.Request, creds aws.Credentials) string {
	t.Helper()
	signedAt, err := time.Parse("20060102T150405Z", received.Header.Get("X-Amz-Date"))
	assert.NoError(t, err)
	u := &url.URL{Scheme: "https", Host: received.Host, Path: received.URL.Path, RawPath: received.URL.RawPath}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u.String(), nil)
	assert.NoError(t, err)
	req.Host = received.Host
	auth := received.Header.Get("Authorization")
	signedHeaders := auth[strings.Index(auth, "SignedHeaders=")+len("SignedHeaders=") : strings.Index(auth, ", Signature=")]
	for name := range strings.SplitSeq(signedHeaders, ";") {
		if name != "host" {
			req.Header.Set(name, received.Header.Get(name))
		}
	}
	req.Header.Del("Authorization")
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	assert.NoError(t, signer.SignHTTP(t.Context(), creds, req, s3EmptyPayloadHash, "s3", testS3Region, signedAt))
	return req.Header.Get("Authorization")
}

func TestS3ObjectsSignsAndCachesObjects(t *testing.T) {
	origin := newS3TestOrigin(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("archive"))
	})
	creds := credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "session-token")
	mux := newTestS3Objects(t, testS3Config(), origin, creds)

	target := "/" + testS3Host + "/bazel/archives/tool%2Bv1%20final.tar.gz"
	w := serveS3(t, mux, target, map[string]string{
		"Authorization":       "Bearer client",
		"X-Amz-Request-Payer": "requester",
		"X-Amz-Version-Id":    "abc",
		"Cookie":              "session=1",
	})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "archive", w.Body.String())
	assert.Equal(t, "miss", w.Header().Get(handler.CacheResultHeader))

	received := origin.last.Load()
	assert.Equal(t, testS3Host, received.Host)
	assert.Equal(t, "/bazel/archives/tool%2Bv1%20final.tar.gz", received.URL.EscapedPath())
	assert.Equal(t, testS3Owner, received.Header.Get("X-Amz-Expected-Bucket-Owner"))
	assert.Equal(t, s3EmptyPayloadHash, received.Header.Get("X-Amz-Content-Sha256"))
	assert.Equal(t, "session-token", received.Header.Get("X-Amz-Security-Token"))
	assert.Equal(t, "", received.Header.Get("X-Amz-Request-Payer"))
	assert.Equal(t, "", received.Header.Get("X-Amz-Version-Id"))
	assert.Equal(t, "", received.Header.Get("Cookie"))
	assert.True(t, strings.HasPrefix(received.Header.Get("Authorization"),
		"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261020/us-east-1/s3/aws4_request"))
	resolved, err := creds.Retrieve(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, resign(t, received, resolved), received.Header.Get("Authorization"))

	w = serveS3(t, mux, target, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "archive", w.Body.String())
	assert.Equal(t, "hit", w.Header().Get(handler.CacheResultHeader))
	assert.Equal(t, int32(1), origin.requests.Load())
}

func TestS3ObjectsUsesDefaultChainCredentialsWithoutSessionToken(t *testing.T) {
	origin := newS3TestOrigin(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux := newTestS3Objects(t, testS3Config(), origin, nil)

	w := serveS3(t, mux, "/"+testS3Host+"/bazel/archives/a.zip", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", origin.last.Load().Header.Get("X-Amz-Security-Token"))
}

func TestS3ObjectsRejectsUnadmittedRequests(t *testing.T) {
	origin := newS3TestOrigin(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) })
	mux := newTestS3Objects(t, testS3Config(), origin, nil)

	for _, target := range []string{
		"/" + testS3Host + "/other/file.tar.gz",
		"/" + testS3Host + "/bazel/archives",
		"/" + testS3Host + "/bazel/archivesx/file.tar.gz",
		"/" + testS3Host + "/bazel/archives/file.tar.gz?versionId=1",
		"/" + testS3Host + "/bazel/archives/file.tar.gz?list-type=2",
		"/" + testS3Host + "/bazel/archives/%2E%2E/%2E%2E/other/file",
		"/" + testS3Host + "/bazel/archives/a%2F%2Fb",
		"/" + testS3Host + "/bazel/archives/a%00b",
	} {
		w := serveS3(t, mux, target, nil)
		assert.Equal(t, http.StatusNotFound, w.Code, target)
	}
	assert.Equal(t, int32(0), origin.requests.Load())

	w := serveS3(t, mux, "/other-bucket.s3.us-east-1.amazonaws.com/bazel/archives/file.tar.gz", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, int32(0), origin.requests.Load())
}

func TestS3ObjectsDoesNotCacheErrorsOrPartialContent(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusForbidden)
	origin := newS3TestOrigin(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte("body"))
	})
	mux := newTestS3Objects(t, testS3Config(), origin, nil)
	target := "/" + testS3Host + "/bazel/archives/a.zip"

	assert.Equal(t, http.StatusForbidden, serveS3(t, mux, target, nil).Code)
	status.Store(http.StatusPartialContent)
	assert.Equal(t, http.StatusPartialContent, serveS3(t, mux, target, map[string]string{"Range": "bytes=0-1"}).Code)
	assert.Equal(t, "bytes=0-1", origin.last.Load().Header.Get("Range"))
	status.Store(http.StatusOK)
	assert.Equal(t, http.StatusOK, serveS3(t, mux, target, nil).Code)
	assert.Equal(t, int32(3), origin.requests.Load())
}

func TestS3ObjectsDoesNotFollowRedirects(t *testing.T) {
	origin := newS3TestOrigin(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://example-artifacts.s3.us-west-2.amazonaws.com/bazel/archives/a.zip")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	mux := newTestS3Objects(t, testS3Config(), origin, nil)

	w := serveS3(t, mux, "/"+testS3Host+"/bazel/archives/a.zip", nil)
	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, int32(1), origin.requests.Load())
}

func TestS3ObjectsValidatesConfig(t *testing.T) {
	for name, mutate := range map[string]func(*S3ObjectsConfig){
		"dotted bucket":       func(c *S3ObjectsConfig) { c.Bucket = "example.artifacts" },
		"uppercase bucket":    func(c *S3ObjectsConfig) { c.Bucket = "Example" },
		"region":              func(c *S3ObjectsConfig) { c.Region = "us-east-1/../x" },
		"owner":               func(c *S3ObjectsConfig) { c.ExpectedOwner = "" },
		"no prefixes":         func(c *S3ObjectsConfig) { c.Prefixes = nil },
		"root prefix":         func(c *S3ObjectsConfig) { c.Prefixes = []string{"/"} },
		"empty prefix":        func(c *S3ObjectsConfig) { c.Prefixes = []string{""} },
		"unterminated prefix": func(c *S3ObjectsConfig) { c.Prefixes = []string{"bazel"} },
		"dot prefix":          func(c *S3ObjectsConfig) { c.Prefixes = []string{"bazel/../"} },
		"negative ttl":        func(c *S3ObjectsConfig) { c.TTL = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			config := testS3Config()
			mutate(&config)
			assert.Error(t, validateS3ObjectsConfig(config))
		})
	}
	assert.NoError(t, validateS3ObjectsConfig(testS3Config()))
}

func TestS3ObjectsLoadsFromHCL(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	ast, err := hcl.ParseString(`
s3-objects "example-artifacts" {
  region         = "us-east-1"
  expected-owner = "111122223333"
  prefixes       = ["bazel/archives/", "release/"]
}
`)
	assert.NoError(t, err)
	block := ast.Entries[0].(*hcl.Block) //nolint:forcetypeassert
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = memCache.Close() })

	r := NewRegistry()
	RegisterS3Objects(r)
	s, err := r.Create(ctx, "s3-objects", block, memCache, http.NewServeMux(), nil)
	assert.NoError(t, err)
	assert.Equal(t, "s3-objects:example-artifacts", s.String())
	assert.Equal(t, []string{"bazel/archives/", "release/"}, s.(*S3Objects).prefixes) //nolint:forcetypeassert
}
