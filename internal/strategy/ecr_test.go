package strategy //nolint:testpackage // White-box coverage injects the token source and base transport.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/handler"
)

const (
	testECRRegistry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
	testECRS3Host   = "prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com"
	testECRName     = "ecr-public/buildkite/helm/agent-stack-k8s"
	testOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	testPresigned   = "/blob?X-Amz-Signature=presigned-secret"
	plainHTTP       = "http"
)

type fakeECR struct {
	server *httptest.Server

	manifest      []byte
	blob          []byte
	acceptedToken string
	chunked       bool   // flush manifests before the body so they carry no Content-Length
	missingRepo   bool   // answer blob reads 404 NAME_UNKNOWN, as a never-pulled pull-through repo does
	insecureS3    bool   // redirect blob GETs to plain http
	noRedirect    bool   // answer blob GETs 200 with the bytes instead of redirecting
	headDigest    string // overrides the Docker-Content-Digest a blob HEAD reports
	headNoLength  bool   // answer blob HEADs without Content-Length
	location      string // overrides the Location a blob GET redirects to
	redirectCode  int    // overrides the blob GET redirect status
	tooMany       bool   // answer blob reads 429
	redirectManif bool   // redirect manifest reads to S3, where the bytes are served
	partial       bool   // answer manifest reads 206
	denyBody      string

	mu             sync.Mutex
	registryCalls  int
	s3Calls        int
	lastRegistry   http.Header
	lastS3         http.Header
	lastMethod     string
	lastRegistryAt string
}

func (f *fakeECR) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Host == testECRS3Host {
		f.s3Calls++
		f.lastS3 = r.Header.Clone()
		switch {
		case r.Header.Get("Authorization") != "":
			// S3 rejects a presigned URL that also carries credentials.
			w.WriteHeader(http.StatusBadRequest)
		case f.redirectManif:
			w.Header().Set("Content-Type", testOCIManifest)
			_, _ = w.Write(f.manifest)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
		return
	}
	f.registryCalls++
	f.lastRegistry = r.Header.Clone()
	f.lastMethod = r.Method
	f.lastRegistryAt = r.URL.Path
	if f.denyBody != "" {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, f.denyBody)
		return
	}
	if r.Header.Get("Authorization") != "Basic "+f.acceptedToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, strings.Repeat("0", 64)):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"account 123456789012"}]}`)
	case strings.Contains(r.URL.Path, "/manifests/") && f.redirectManif:
		http.Redirect(w, r, "https://"+testECRS3Host+"/manifest", http.StatusTemporaryRedirect)
	case strings.Contains(r.URL.Path, "/manifests/"):
		// ECR omits Docker-Content-Digest on manifest GETs.
		w.Header().Set("Content-Type", testOCIManifest)
		// An upstream must not choose how long Cachew keeps an entry.
		w.Header().Set("X-Cachew-Expires-At", "2999-01-01T00:00:00Z")
		switch {
		case f.partial:
			w.WriteHeader(http.StatusPartialContent)
		case f.chunked:
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(f.manifest)
	case f.missingRepo:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"code":"NAME_UNKNOWN"}]}`)
	case f.tooMany:
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	case r.Method == http.MethodHead:
		digest := testDigest(f.blob)
		if f.headDigest != "" {
			digest = f.headDigest
		}
		if !f.headNoLength {
			w.Header().Set("Content-Length", strconv.Itoa(len(f.blob)))
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("X-Amz-Request-Id", "upstream-detail")
		w.WriteHeader(http.StatusOK)
	case f.noRedirect:
		_, _ = w.Write(f.blob)
	default:
		location := ecrSchemeHTTPS + "://" + testECRS3Host + testPresigned
		if f.insecureS3 {
			location = plainHTTP + "://" + testECRS3Host + testPresigned
		}
		if f.location != "" {
			location = f.location
		}
		code := http.StatusTemporaryRedirect
		if f.redirectCode != 0 {
			code = f.redirectCode
		}
		w.Header().Set("Location", location)
		w.Header().Set("X-Amz-Request-Id", "upstream-detail")
		w.Header().Set("Set-Cookie", "upstream=1")
		w.WriteHeader(code)
	}
}

func (f *fakeECR) counts() (registry, s3 int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registryCalls, f.s3Calls
}

// pinTransport sends every host to the fake server, keeping the original host
// so the fake can tell the registry from S3.
type pinTransport struct{ backend *httptest.Server }

func (p pinTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Host = req.URL.Host
	req.URL.Scheme = plainHTTP
	req.URL.Host = p.backend.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req) //nolint:wrapcheck // test transport
}

// fakeTokens mints tok-1, tok-2, ... and advances only when the current
// generation is rejected, as originTokenManager does.
type fakeTokens struct {
	mu       sync.Mutex
	gen      uint64
	rejected []uint64
	err      error
}

func (f *fakeTokens) Token(_ context.Context, rejected uint64) (originToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = append(f.rejected, rejected)
	if f.err != nil {
		return originToken{}, f.err
	}
	if f.gen == 0 || (rejected != 0 && rejected >= f.gen) {
		f.gen++
	}
	return originToken{value: "tok-" + string(rune('0'+f.gen)), generation: f.gen}, nil
}

type ecrTest struct {
	fake   *fakeECR
	mux    *http.ServeMux
	cache  cache.Cache
	ctx    context.Context
	tokens *fakeTokens
	ecr    *ECR
}

func setupECRTest(t *testing.T, configure func(*fakeECR)) *ecrTest {
	t.Helper()
	return setupECRTestWith(t, configure, nil, []string{"ecr-public/buildkite/", "docker-hub/library/alpine"})
}

func setupECRTestWith(t *testing.T, configure func(*fakeECR), override cache.Cache, repositories []string) *ecrTest {
	t.Helper()
	fake := &fakeECR{manifest: []byte(`{"schemaVersion":2}`), blob: []byte("chart-tarball-bytes"), acceptedToken: "tok-1"}
	configure(fake)
	fake.server = httptest.NewServer(fake)
	t.Cleanup(fake.server.Close)

	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { memCache.Close() })
	var c cache.Cache = memCache
	if override != nil {
		c = override
	}

	tokens := &fakeTokens{}
	mux := http.NewServeMux()
	config := ecrConfigWithDefaults(ECRConfig{
		Registry:     testECRRegistry,
		RoleARN:      "arn:aws:iam::123456789012:role/cachew-ecr-read",
		Repositories: repositories,
	})
	s, err := newECR(config, tokens, pinTransport{backend: fake.server}, c, mux, newInternalTestSpools(t))
	assert.NoError(t, err)
	assert.Equal(t, "ecr:"+testECRRegistry, s.String())
	return &ecrTest{fake: fake, mux: mux, cache: c, ctx: ctx, tokens: tokens, ecr: s}
}

func (e *ecrTest) do(method, path string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil).WithContext(e.ctx)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func testDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestECRServesManifestsByDigestThenCaches(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.manifest)

	w := e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, e.fake.manifest, w.Body.Bytes())
	assert.Equal(t, testOCIManifest, w.Header().Get("Content-Type"))
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"), "ECR omits it on GET; clients expect it")
	assert.Equal(t, "", w.Header().Get(cache.ExpirationKey), "the cache's expiry stays internal")
	assert.Contains(t, e.fake.lastRegistry.Get("Accept"), testOCIManifest)
	assert.Equal(t, "Basic tok-1", e.fake.lastRegistry.Get("Authorization"))

	// The prefixed mount shares the cache entry, and HEAD is served from it.
	w = e.do(http.MethodHead, "/"+testECRRegistry+"/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))
	assert.Equal(t, handler.CacheResultHit, w.Header().Get(handler.CacheResultHeader))
	assert.Equal(t, "", w.Header().Get(cache.ExpirationKey))
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, handler.CacheResultHit, w.Header().Get(handler.CacheResultHeader))
	assert.Equal(t, "", w.Header().Get(cache.ExpirationKey))
	registry, _ := e.fake.counts()
	assert.Equal(t, 1, registry)

	headers, err := e.cache.Stat(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, testECRName, digest)))
	assert.NoError(t, err, "the manifest is stored under the strategy's own key")
	expiresAt, err := time.Parse(time.RFC3339Nano, headers.Get(cache.ExpirationKey))
	assert.NoError(t, err, "the manifest TTL is pinned so no cache tier can extend it, whatever the upstream sent")
	assert.True(t, time.Until(expiresAt) > defaultECRManifestTTL-time.Minute && time.Until(expiresAt) <= defaultECRManifestTTL)
	_, _, err = e.cache.Open(e.ctx, cache.NewKey("https://"+testECRRegistry+"/v2/"+testECRName+"/manifests/"+digest))
	assert.IsError(t, err, os.ErrNotExist, "the key must not collide with a URL-shaped key another strategy could write")
}

func TestECRRedirectsBlobGetsToS3(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	path := "/v2/" + testECRName + "/blobs/" + testDigest(e.fake.blob)

	w := e.do(http.MethodGet, path)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Equal(t, "https://"+testECRS3Host+testPresigned, w.Header().Get("Location"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "the presigned URL expires")
	assert.Equal(t, "", w.Header().Get("X-Amz-Request-Id"), "only Location is copied")
	assert.Equal(t, "", w.Header().Get("Set-Cookie"))

	// The signed URL is passed on byte for byte; re-serializing it through
	// url.URL would, for example, lowercase the scheme.
	signed := "HTTPS://" + testECRS3Host + "/blob%7Ekey?X-Amz-Signature=sig&X-Amz-Expires=3600"
	e = setupECRTest(t, func(f *fakeECR) { f.location = signed })
	w = e.do(http.MethodGet, path)
	assert.Equal(t, signed, w.Header().Get("Location"))
	assert.Equal(t, http.MethodGet, e.fake.lastMethod)
	assert.Equal(t, "Basic tok-1", e.fake.lastRegistry.Get("Authorization"))
	_, s3 := e.fake.counts()
	assert.Equal(t, 0, s3, "the proxy never fetches blob bytes")

	w = e.do(http.MethodGet, "/"+testECRRegistry+path)
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	registry, _ := e.fake.counts()
	assert.Equal(t, 2, registry, "redirects are not cached")
}

func TestECRAnswersBlobHeadWithECRsMetadata(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.blob)

	w := e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, http.MethodHead, e.fake.lastMethod)
	assert.Equal(t, strconv.Itoa(len(e.fake.blob)), w.Header().Get("Content-Length"))
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))
	assert.Equal(t, "", w.Header().Get("X-Amz-Request-Id"), "only the length and digest are passed through")

	e = setupECRTest(t, func(f *fakeECR) { f.headDigest = testDigest([]byte("something else")) })
	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusBadGateway, w.Code, "a HEAD never vouches for a digest ECR did not report")

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/sha256:"+strings.Repeat("0", 64))
	assert.Equal(t, http.StatusNotFound, w.Code)

	e = setupECRTest(t, func(f *fakeECR) { f.headNoLength = true })
	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusBadGateway, w.Code, "a blob HEAD without a length is not passed through")

	e = setupECRTest(t, func(f *fakeECR) { f.tooMany = true })
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		w = e.do(method, "/v2/"+testECRName+"/blobs/"+digest)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "%s: a 429 is kept so clients back off", method)
		assert.Equal(t, "7", w.Header().Get("Retry-After"), method)
	}
}

func TestECRRefusesUnusableBlobRedirects(t *testing.T) {
	digest := testDigest([]byte("chart-tarball-bytes"))
	for name, configure := range map[string]func(*fakeECR){
		"relative Location":    func(f *fakeECR) { f.location = testPresigned },
		"302 instead of 307":   func(f *fakeECR) { f.redirectCode = http.StatusFound },
		"unparseable Location": func(f *fakeECR) { f.location = "https://" + testECRS3Host + "/%zz?X-Amz-Signature=presigned-secret" },
	} {
		e := setupECRTest(t, configure)
		w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+digest)
		assert.Equal(t, http.StatusBadGateway, w.Code, name)
		assert.Equal(t, "", w.Header().Get("Location"), name)
		assert.NotContains(t, w.Body.String(), "presigned-secret", name)
		assert.NotContains(t, w.Body.String(), "X-Amz-Signature", name)
	}

	e := setupECRTest(t, func(f *fakeECR) { f.insecureS3 = true })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Equal(t, "", w.Header().Get("Location"))
	assert.NotContains(t, w.Body.String(), "presigned-secret")
	assert.NotContains(t, w.Body.String(), "X-Amz-Signature")

	e = setupECRTest(t, func(f *fakeECR) { f.noRedirect = true })
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusBadGateway, w.Code, "blob bytes are never streamed or cached")
	assert.NotContains(t, w.Body.String(), string(e.fake.blob))
}

func TestECRSendsCredentialsToTheRegistryHopOnly(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.redirectManif = true })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+testDigest(e.fake.manifest))
	assert.Equal(t, http.StatusOK, w.Code, "a redirected manifest is followed; S3 answers 400 if the token comes along")
	assert.Equal(t, e.fake.manifest, w.Body.Bytes())
	assert.Equal(t, "Basic tok-1", e.fake.lastRegistry.Get("Authorization"))
	assert.Equal(t, "", e.fake.lastS3.Get("Authorization"))
	assert.Equal(t, []string{"Accept", "Accept-Encoding", "User-Agent"}, headerNames(e.fake.lastS3), "the redirect hop gets the same headers, minus the token")
}

func TestECRServesOnlyListedRepositories(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.blob)
	for _, name := range []string{"ecr-public/other/chart", "docker-hub/library/alpine-evil", "docker-hub/library", "ecr-public/buildkite"} {
		w := e.do(http.MethodGet, "/v2/"+name+"/blobs/"+digest)
		assert.Equal(t, http.StatusNotFound, w.Code, name)
	}
	registry, _ := e.fake.counts()
	assert.Equal(t, 0, registry)
	assert.Equal(t, 0, len(e.tokens.rejected), "a refused repository mints no token")

	assert.Equal(t, http.StatusTemporaryRedirect, e.do(http.MethodGet, "/v2/docker-hub/library/alpine/blobs/"+digest).Code, "an exact entry is served")
}

func TestECRServesEveryRepositoryWhenNoneAreListed(t *testing.T) {
	e := setupECRTestWith(t, func(*fakeECR) {}, nil, nil)
	w := e.do(http.MethodGet, "/v2/anything/the-role-can/read/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code, "the role's IAM scope is the boundary")
}

func TestECRManifestHeadAnswersFromVerifiedCacheEntries(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.manifest)

	w := e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, handler.CacheResultMiss, w.Header().Get(handler.CacheResultHeader))
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))
	assert.Equal(t, 0, w.Body.Len())

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, handler.CacheResultHit, w.Header().Get(handler.CacheResultHeader))
	registry, _ := e.fake.counts()
	assert.Equal(t, 1, registry, "the second HEAD is answered from the cache entry's metadata")

	wrong := testDigest([]byte("not-the-manifest"))
	w = e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/"+wrong)
	assert.Equal(t, http.StatusBadGateway, w.Code, "a HEAD never vouches for bytes that failed verification")
	assert.Equal(t, "", w.Header().Get("Docker-Content-Digest"))

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/sha256:"+strings.Repeat("0", 64))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestECRManifestHeadAnswersAVerifiedFillTheCacheDidNotKeep(t *testing.T) {
	repos := []string{"ecr-public/"}
	e := setupECRTestWith(t, func(*fakeECR) {}, cache.NoOpCache(), repos)
	digest := testDigest(e.fake.manifest)
	w := e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, http.StatusOK, w.Code, "verified bytes are vouched for even when the cache drops them")
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/"+testDigest([]byte("not-the-manifest")))
	assert.Equal(t, http.StatusBadGateway, w.Code)

	e = setupECRTestWith(t, func(f *fakeECR) { f.manifest = nil }, cache.NoOpCache(), repos)
	w = e.do(http.MethodHead, "/v2/"+testECRName+"/manifests/sha256:"+emptySHA256)
	assert.Equal(t, http.StatusOK, w.Code, "an empty body is verified without a single write")
}

func TestECRAnswersTheVersionCheckLocally(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	for _, path := range []string{"/v2/", "/" + testECRRegistry + "/v2/"} {
		w := e.do(http.MethodGet, path)
		assert.Equal(t, http.StatusOK, w.Code, path)
		assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-Api-Version"))
		assert.Equal(t, "{}", w.Body.String())
	}
	registry, _ := e.fake.counts()
	assert.Equal(t, 0, registry)
	assert.Equal(t, 0, len(e.tokens.rejected), "the version check needs no credentials")
}

func TestECRServesOnlyDigestPaths(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.blob)
	for _, path := range []string{
		"/v2/" + testECRName + "/manifests/latest",
		"/v2/" + testECRName + "/tags/list",
		"/v2/_catalog",
		"/v2/Buildkite/chart/blobs/" + digest,
		"/v2/" + testECRName + "/blobs/sha512:" + strings.Repeat("a", 128),
		"/v2/" + testECRName + "/blobs/uploads/",
	} {
		w := e.do(http.MethodGet, path)
		assert.Equal(t, http.StatusNotFound, w.Code, path)
	}
	registry, _ := e.fake.counts()
	assert.Equal(t, 0, registry)
	assert.Equal(t, 0, len(e.tokens.rejected))
}

func TestECRManifestDigestMismatchIsNeitherCachedNorDelivered(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	wrong := testDigest([]byte("what-the-caller-asked-for"))

	// A real server and client: the recorder cannot observe a response that
	// is cut short of its Content-Length.
	server := httptest.NewUnstartedServer(e.mux)
	server.Config.BaseContext = func(net.Listener) context.Context { return e.ctx }
	server.Start()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{}}
	resp, err := client.Get(server.URL + "/v2/" + testECRName + "/manifests/" + wrong)
	if err == nil {
		// Headers can be committed before the digest is known; the body is then cut short.
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.IsError(t, err, io.ErrUnexpectedEOF)
	}
	assert.Error(t, err, "the client must not receive a complete response whose digest does not match")

	_, _, err = e.cache.Open(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, testECRName, wrong)))
	assert.IsError(t, err, os.ErrNotExist, "bytes that do not match the digest must not be cached")
}

func TestECRRetriesOnceWithAFreshToken(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.acceptedToken = "tok-2" })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Equal(t, []uint64{0, 1}, e.tokens.rejected, "the rejected generation is reported so a concurrent refresh can be reused")

	e.fake.acceptedToken = "never"
	manifest := "/v2/" + testECRName + "/manifests/" + testDigest(e.fake.manifest)
	w = e.do(http.MethodGet, manifest)
	assert.Equal(t, http.StatusBadGateway, w.Code, "the proxy's own credential failure is a gateway error, not a client login problem")
	assert.Equal(t, []uint64{0, 1, 0, 0}, e.tokens.rejected, "within the refresh interval only a plain lookup, which mints nothing new")
	registry, _ := e.fake.counts()
	assert.Equal(t, 3, registry)
	_, _, err := e.cache.Open(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, testECRName, testDigest(e.fake.manifest))))
	assert.IsError(t, err, os.ErrNotExist)

	now := time.Now().Add(2 * ecrForcedRefreshInterval)
	e.ecr.now = func() time.Time { return now }
	w = e.do(http.MethodGet, manifest)
	assert.Equal(t, http.StatusBadGateway, w.Code, "after the interval one refresh is tried, then the rejection is a 502")
	assert.Equal(t, []uint64{0, 1, 0, 0, 0, 2}, e.tokens.rejected)
}

// scriptedTokens returns its tokens in order, then repeats the last one.
type scriptedTokens struct {
	mu       sync.Mutex
	script   []originToken
	rejected []uint64
}

func (s *scriptedTokens) Token(_ context.Context, rejected uint64) (originToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejected = append(s.rejected, rejected)
	token := s.script[0]
	if len(s.script) > 1 {
		s.script = s.script[1:]
	}
	return token, nil
}

func TestECRReusesATokenAnotherRequestMinted(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.acceptedToken = "tok-2" })
	// This request started with tok-1 while another one, rejected a moment
	// earlier, used up the refresh interval minting tok-2.
	tokens := &scriptedTokens{script: []originToken{{value: "tok-1", generation: 1}, {value: "tok-2", generation: 2}}}
	e.ecr.tokens = tokens
	e.ecr.lastForcedRefresh.Store(time.Now().UnixNano())

	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code, "the newer token is reused even though this request may not mint")
	assert.Equal(t, []uint64{0, 0}, tokens.rejected, "no forced refresh inside the interval")
}

func TestECRNeverEchoesUpstreamErrorDetail(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) {
		f.denyBody = `{"errors":[{"code":"DENIED","message":"User: arn:aws:sts::123456789012:assumed-role/cachew-ecr-read/session is not authorized"}]}`
	})
	for _, kind := range []string{ecrManifests, ecrBlobs} {
		w := e.do(http.MethodGet, "/v2/"+testECRName+"/"+kind+"/"+testDigest(e.fake.blob))
		assert.Equal(t, http.StatusBadGateway, w.Code, kind)
		assert.NotContains(t, w.Body.String(), "arn:aws")
		assert.NotContains(t, w.Body.String(), "DENIED")
	}

	e = setupECRTest(t, func(*fakeECR) {})
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/sha256:"+strings.Repeat("0", 64))
	assert.Equal(t, http.StatusNotFound, w.Code, "a 404 is kept so mirror clients fall back")
	assert.NotContains(t, w.Body.String(), "MANIFEST_UNKNOWN")
	assert.NotContains(t, w.Body.String(), "123456789012")

	e.tokens.err = errors.New("AccessDenied: User: arn:aws:sts::123456789012:assumed-role/node is not authorized to perform sts:AssumeRole")
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.NotContains(t, w.Body.String(), "arn:aws")
}

func TestECRRefusesPartialResponses(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.partial = true })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+testDigest(e.fake.manifest))
	assert.Equal(t, http.StatusBadGateway, w.Code, "a 206 would skip digest verification")
}

func TestECRRejectsAConflictingRootMount(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	other := ECRConfig{Registry: "210987654321.dkr.ecr.us-west-2.amazonaws.com", RoleARN: "arn:aws:iam::210987654321:role/read"}
	_, err := newECR(ecrConfigWithDefaults(other), e.tokens, http.DefaultTransport, e.cache, e.mux, newInternalTestSpools(t))
	assert.Error(t, err, "a second registry cannot also own /v2/")
	assert.Contains(t, err.Error(), "prefix-only")

	other.PrefixOnly = true
	_, err = newECR(ecrConfigWithDefaults(other), e.tokens, http.DefaultTransport, e.cache, e.mux, newInternalTestSpools(t))
	assert.NoError(t, err)

	_, err = newECR(ecrConfigWithDefaults(other), e.tokens, http.DefaultTransport, e.cache, e.mux, newInternalTestSpools(t))
	assert.Error(t, err, "the same registry twice is a configuration error, not a ServeMux panic")
	assert.Contains(t, err.Error(), "more than once")
}

func TestECRBuildsUpstreamHeadersFromScratch(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	client := []string{
		"Accept-Encoding", "gzip",
		"Range", "bytes=0-4",
		"If-None-Match", `"stale"`,
		"Authorization", "Basic Y2xpZW50OnNlY3JldA==",
		"Cookie", "session=abc",
		"X-Forwarded-For", "10.0.0.1",
		"X-Amz-Foo", "bar", // S3 rejects a presigned URL with any unsigned X-Amz-* header
	}

	w := e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+testDigest(e.fake.manifest), client...)
	assert.Equal(t, http.StatusOK, w.Code, "a Range request must not become an unverified 206")
	assert.Equal(t, e.fake.manifest, w.Body.Bytes())
	assert.Equal(t, []string{"Accept", "Accept-Encoding", "Authorization", "User-Agent"}, headerNames(e.fake.lastRegistry))
	assert.Equal(t, "identity", e.fake.lastRegistry.Get("Accept-Encoding"))
	assert.Equal(t, ecrUserAgent, e.fake.lastRegistry.Get("User-Agent"))
	assert.Equal(t, "Basic tok-1", e.fake.lastRegistry.Get("Authorization"), "the client's credentials never reach ECR")

	// The cache does not vary on the client's encoding.
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+testDigest(e.fake.manifest))
	assert.Equal(t, handler.CacheResultHit, w.Header().Get(handler.CacheResultHeader))

	e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob), client...)
	assert.Equal(t, []string{"Accept-Encoding", "Authorization", "User-Agent"}, headerNames(e.fake.lastRegistry))
}

func TestECRPropagatesMissingRepositoriesWithoutCaching(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.missingRepo = true })
	path := "/v2/" + testECRName + "/blobs/" + testDigest(e.fake.blob)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, path).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, path).Code)

	missing := "/v2/" + testECRName + "/manifests/sha256:" + strings.Repeat("0", 64)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, missing).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, missing).Code)
	registry, _ := e.fake.counts()
	assert.Equal(t, 4, registry, "a 404 is not cached, so a later manifest pull that creates the repository is seen")
}

func TestECRRefusesManifestBodiesItCannotTruncate(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.chunked = true })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+testDigest(e.fake.manifest))
	assert.Equal(t, http.StatusBadGateway, w.Code)

	e = setupECRTest(t, func(f *fakeECR) { f.manifest = nil })
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/sha256:"+emptySHA256)
	assert.Equal(t, http.StatusOK, w.Code, "an empty body is valid when the digest is the empty digest")
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+testDigest([]byte("not-empty")))
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.NotContains(t, w.Body.String(), "/v2/", "errors name the host, not the path")
}

func TestDigestVerifyingBodyKeepsHeldBytesAcrossSmallReads(t *testing.T) {
	body := make([]byte, 3*digestHoldback+123)
	for i := range body {
		body[i] = byte(i * 7)
	}
	read := func(expected string) ([]byte, error) {
		v := &digestVerifyingBody{ReadCloser: io.NopCloser(strings.NewReader(string(body))), hash: sha256.New(), expected: expected}
		var out []byte
		p := make([]byte, 777)
		for {
			n, err := v.Read(p)
			out = append(out, p[:n]...)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return out, nil
				}
				return out, err
			}
		}
	}
	out, err := read(strings.TrimPrefix(testDigest(body), "sha256:"))
	assert.NoError(t, err)
	assert.Equal(t, body, out, "every byte is released once the digest verifies")

	out, err = read(strings.TrimPrefix(testDigest([]byte("other")), "sha256:"))
	assert.IsError(t, err, errDigestFailed)
	assert.True(t, len(out) <= len(body)-digestHoldback, "the held tail is never released on a mismatch")
}

func TestECRConfigDefaults(t *testing.T) {
	config := ecrConfigWithDefaults(ECRConfig{})
	assert.Equal(t, 72*time.Hour, config.ManifestTTL)
	assert.Equal(t, 15*time.Second, config.CredentialTimeout)
	assert.Equal(t, 60*time.Second, config.OriginHeaderTimeout)
}

func TestECRRejectsBadConfig(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/cachew-ecr-read"
	for _, config := range []ECRConfig{
		{Registry: "ghcr.io", RoleARN: role},
		{Registry: "public.ecr.aws", RoleARN: role},
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", RoleARN: role},
		{Registry: testECRRegistry + "/path", RoleARN: role},
		{Registry: testECRRegistry},
		{Registry: testECRRegistry, RoleARN: role, Repositories: []string{"/"}},
		{Registry: testECRRegistry, RoleARN: role, Repositories: []string{"Upper/"}},
		{Registry: testECRRegistry, RoleARN: role, ManifestTTL: -time.Hour},
	} {
		_, err := validateECRConfig(config)
		assert.Error(t, err, "%+v", config)
	}
	region, err := validateECRConfig(ECRConfig{Registry: testECRRegistry, RoleARN: role})
	assert.NoError(t, err, "repositories is optional")
	assert.Equal(t, "us-east-1", region)
	_, err = validateECRConfig(ECRConfig{Registry: testECRRegistry, RoleARN: role, Repositories: []string{"ecr-public/", "base/alpine"}})
	assert.NoError(t, err)
}

type fakeECRAuthorization struct {
	output *awsecr.GetAuthorizationTokenOutput
	err    error
}

func (f fakeECRAuthorization) GetAuthorizationToken(
	context.Context, *awsecr.GetAuthorizationTokenInput, ...func(*awsecr.Options),
) (*awsecr.GetAuthorizationTokenOutput, error) {
	return f.output, f.err
}

func TestECRTokenMinterFeedsTheTokenManager(t *testing.T) {
	ctx := context.Background()
	expires := time.Now().Add(12 * time.Hour)
	manager := newOriginTokenManager("ECR", time.Second, ecrTokenMinter(fakeECRAuthorization{output: &awsecr.GetAuthorizationTokenOutput{
		AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: aws.String("QVdTOnBhc3N3b3Jk"), ExpiresAt: aws.Time(expires)}},
	}}), time.Now)
	token, err := manager.Token(ctx, 0)
	assert.NoError(t, err)
	assert.Equal(t, "QVdTOnBhc3N3b3Jk", token.value)

	manager = newOriginTokenManager("ECR", time.Second, ecrTokenMinter(fakeECRAuthorization{output: &awsecr.GetAuthorizationTokenOutput{}}), time.Now)
	_, err = manager.Token(ctx, 0)
	assert.EqualError(t, err, "ECR returned an incomplete authorization token")

	denied := errors.New("AccessDeniedException")
	manager = newOriginTokenManager("ECR", time.Second, ecrTokenMinter(fakeECRAuthorization{err: denied}), time.Now)
	_, err = manager.Token(ctx, 0)
	assert.IsError(t, err, denied)
	assert.Contains(t, err.Error(), "mint ECR authorization token")
}
