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
)

const (
	testECRRegistry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
	testECRS3Host   = "prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com"
	testECRName     = "ecr-public/buildkite/helm/agent-stack-k8s"
	testOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	plainHTTP       = "http"
)

type fakeECR struct {
	server *httptest.Server

	manifest      []byte
	blob          []byte
	acceptedToken string
	chunked       bool // flush before the body so the S3 response carries no Content-Length
	missingRepo   bool // answer blob reads 404 NAME_UNKNOWN, as a never-pulled pull-through repo does
	insecureS3    bool // redirect blob reads to plain http
	partial       bool // answer manifest reads 206
	denyBody      string

	mu             sync.Mutex
	registryGets   int
	s3Gets         int
	lastRegistry   http.Header
	lastS3         http.Header
	lastRegistryAt string
}

func (f *fakeECR) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Host == testECRS3Host {
		f.s3Gets++
		f.lastS3 = r.Header.Clone()
		if r.Header.Get("Authorization") != "" {
			// ECR credentials must never reach the presigned S3 URL.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// An upstream must not choose how long Cachew keeps an entry.
		w.Header().Set("X-Cachew-Expires-At", "2999-01-01T00:00:00Z")
		if f.chunked {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(f.blob)
		return
	}
	f.registryGets++
	f.lastRegistry = r.Header.Clone()
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
		w.WriteHeader(http.StatusNotFound)
	case strings.Contains(r.URL.Path, "/manifests/"):
		// ECR omits Docker-Content-Digest on manifest GETs.
		w.Header().Set("Content-Type", testOCIManifest)
		if f.partial {
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write(f.manifest)
	case f.missingRepo:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"code":"NAME_UNKNOWN"}]}`)
	default:
		scheme := httpsScheme
		if f.insecureS3 {
			scheme = plainHTTP
		}
		http.Redirect(w, r, scheme+"://"+testECRS3Host+"/blob?X-Amz-Signature=presigned-secret", http.StatusTemporaryRedirect)
	}
}

func (f *fakeECR) counts() (registry, s3 int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registryGets, f.s3Gets
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
// generation is rejected, as codeArtifactTokenManager does.
type fakeTokens struct {
	mu       sync.Mutex
	gen      uint64
	rejected []uint64
	err      error
}

func (f *fakeTokens) Token(_ context.Context, rejected uint64) (codeArtifactToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = append(f.rejected, rejected)
	if f.err != nil {
		return codeArtifactToken{}, f.err
	}
	if f.gen == 0 || (rejected != 0 && rejected >= f.gen) {
		f.gen++
	}
	return codeArtifactToken{value: "tok-" + string(rune('0'+f.gen)), generation: f.gen}, nil
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
	return setupECRTestWithCache(t, configure, nil)
}

func setupECRTestWithCache(t *testing.T, configure func(*fakeECR), override cache.Cache) *ecrTest {
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
		Repositories: []string{"ecr-public/buildkite/", "docker-hub/library/alpine"},
	})
	s, err := newECR(config, tokens, pinTransport{backend: fake.server}, c, mux)
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
	assert.Equal(t, cacheResultHit, w.Header().Get("X-Cachew-Result"))
	assert.Equal(t, "", w.Header().Get(cache.ExpirationKey))
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/manifests/"+digest)
	assert.Equal(t, cacheResultHit, w.Header().Get("X-Cachew-Result"))
	assert.Equal(t, "", w.Header().Get(cache.ExpirationKey))
	registry, _ := e.fake.counts()
	assert.Equal(t, 1, registry)

	headers, err := e.cache.Stat(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, ecrManifests, testECRName, digest)))
	assert.NoError(t, err, "the manifest is stored under the strategy's own key")
	expiresAt, err := time.Parse(time.RFC3339Nano, headers.Get(cache.ExpirationKey))
	assert.NoError(t, err, "the manifest TTL is pinned so no cache tier can extend it")
	assert.True(t, time.Until(expiresAt) > defaultECRManifestTTL-time.Minute && time.Until(expiresAt) <= defaultECRManifestTTL)
}

func TestECRServesBlobsThroughTheS3RedirectThenCaches(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.blob)

	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, e.fake.blob, w.Body.Bytes())
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))
	assert.Equal(t, "Basic tok-1", e.fake.lastRegistry.Get("Authorization"))
	assert.Equal(t, "", e.fake.lastS3.Get("Authorization"), "credentials stay on the registry hop")

	w = e.do(http.MethodGet, "/"+testECRRegistry+"/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, e.fake.blob, w.Body.Bytes())
	registry, s3 := e.fake.counts()
	assert.Equal(t, 1, registry)
	assert.Equal(t, 1, s3)

	_, _, err := e.cache.Open(e.ctx, cache.NewKey("https://"+testECRRegistry+"/v2/"+testECRName+"/blobs/"+digest))
	assert.IsError(t, err, os.ErrNotExist, "the key must not collide with a URL-shaped key another strategy could write")
	headers, err := e.cache.Stat(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, ecrBlobs, testECRName, digest)))
	assert.NoError(t, err)
	assert.Equal(t, "", headers.Get(cache.ExpirationKey), "blobs use the cache maximum, whatever the upstream sent")
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

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/v2/docker-hub/library/alpine/blobs/"+digest).Code, "an exact entry is served")
}

func TestECRHeadAnswersFromVerifiedCacheEntries(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	digest := testDigest(e.fake.blob)

	w := e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, cacheResultMiss, w.Header().Get("X-Cachew-Result"))
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))
	assert.Equal(t, 0, w.Body.Len())

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, cacheResultHit, w.Header().Get("X-Cachew-Result"))
	_, s3 := e.fake.counts()
	assert.Equal(t, 1, s3, "the second HEAD is answered from the cache entry's metadata")

	wrong := testDigest([]byte("not-the-blob"))
	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+wrong)
	assert.Equal(t, http.StatusBadGateway, w.Code, "a HEAD never vouches for bytes that failed verification")
	assert.Equal(t, "", w.Header().Get("Docker-Content-Digest"))

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/sha256:"+strings.Repeat("0", 64))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestECRHeadAnswersAVerifiedFillTheCacheDidNotKeep(t *testing.T) {
	e := setupECRTestWithCache(t, func(*fakeECR) {}, cache.NoOpCache())
	digest := testDigest(e.fake.blob)
	w := e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusOK, w.Code, "verified bytes are vouched for even when the cache drops them")
	assert.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))

	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/"+testDigest([]byte("not-the-blob")))
	assert.Equal(t, http.StatusBadGateway, w.Code)

	e = setupECRTestWithCache(t, func(f *fakeECR) { f.blob = nil }, cache.NoOpCache())
	w = e.do(http.MethodHead, "/v2/"+testECRName+"/blobs/sha256:"+emptySHA256)
	assert.Equal(t, http.StatusOK, w.Code, "an empty blob is verified without a single write")
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

func TestECRDigestMismatchIsNeitherCachedNorDelivered(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	wrong := testDigest([]byte("what-the-caller-asked-for"))

	// A real server and client: the recorder cannot observe a response that
	// is cut short of its Content-Length.
	server := httptest.NewUnstartedServer(e.mux)
	server.Config.BaseContext = func(net.Listener) context.Context { return e.ctx }
	server.Start()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{}}
	for _, kind := range []string{ecrManifests, ecrBlobs} {
		resp, err := client.Get(server.URL + "/v2/" + testECRName + "/" + kind + "/" + wrong)
		assert.NoError(t, err)
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "headers are committed before the digest can be known")
		assert.IsError(t, err, io.ErrUnexpectedEOF, "%s: the client must not receive a complete body whose digest does not match", kind)

		_, _, err = e.cache.Open(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, kind, testECRName, wrong)))
		assert.IsError(t, err, os.ErrNotExist, "%s: bytes that do not match the digest must not be cached", kind)
	}
}

func TestECRRetriesOnceWithAFreshToken(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.acceptedToken = "tok-2" })
	digest := testDigest(e.fake.blob)

	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+digest)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, e.fake.blob, w.Body.Bytes())
	assert.Equal(t, []uint64{0, 1}, e.tokens.rejected, "the rejected generation is reported so a concurrent refresh can be reused")

	e.fake.acceptedToken = "never"
	manifest := "/v2/" + testECRName + "/manifests/" + testDigest(e.fake.manifest)
	w = e.do(http.MethodGet, manifest)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "within the refresh interval a rejection is returned without minting")
	assert.Equal(t, []uint64{0, 1, 0, 0}, e.tokens.rejected, "only a plain lookup, which mints nothing new")
	registry, _ := e.fake.counts()
	assert.Equal(t, 3, registry)
	_, _, err := e.cache.Open(e.ctx, cache.NewKey(ECRCacheKey(testECRRegistry, ecrManifests, testECRName, testDigest(e.fake.manifest))))
	assert.IsError(t, err, os.ErrNotExist)

	now := time.Now().Add(2 * ecrForcedRefreshInterval)
	e.ecr.now = func() time.Time { return now }
	w = e.do(http.MethodGet, manifest)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "after the interval one refresh is tried, then the rejection is returned")
	assert.Equal(t, []uint64{0, 1, 0, 0, 0, 2}, e.tokens.rejected)
}

// scriptedTokens returns its tokens in order, then repeats the last one.
type scriptedTokens struct {
	mu       sync.Mutex
	script   []codeArtifactToken
	rejected []uint64
}

func (s *scriptedTokens) Token(_ context.Context, rejected uint64) (codeArtifactToken, error) {
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
	tokens := &scriptedTokens{script: []codeArtifactToken{{value: "tok-1", generation: 1}, {value: "tok-2", generation: 2}}}
	e.ecr.tokens = tokens
	e.ecr.lastForcedRefresh.Store(time.Now().UnixNano())

	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusOK, w.Code, "the newer token is reused even though this request may not mint")
	assert.Equal(t, []uint64{0, 0}, tokens.rejected, "no forced refresh inside the interval")
}

func TestECRNeverEchoesUpstreamErrorDetail(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) {
		f.denyBody = `{"errors":[{"code":"DENIED","message":"User: arn:aws:sts::123456789012:assumed-role/cachew-ecr-read/session is not authorized"}]}`
	})
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "arn:aws")
	assert.NotContains(t, w.Body.String(), "DENIED")

	e = setupECRTest(t, func(*fakeECR) {})
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
	other := ECRConfig{Registry: "210987654321.dkr.ecr.us-west-2.amazonaws.com", RoleARN: "arn:aws:iam::210987654321:role/read", Repositories: []string{"base/"}}
	_, err := newECR(ecrConfigWithDefaults(other), e.tokens, http.DefaultTransport, e.cache, e.mux)
	assert.Error(t, err, "a second registry cannot also own /v2/")
	assert.Contains(t, err.Error(), "prefix-only")

	other.PrefixOnly = true
	_, err = newECR(ecrConfigWithDefaults(other), e.tokens, http.DefaultTransport, e.cache, e.mux)
	assert.NoError(t, err)
}

func TestECROwnsTheUpstreamHeaders(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob),
		"Accept-Encoding", "gzip",
		"Range", "bytes=0-4",
		"If-None-Match", `"stale"`,
		"Authorization", "Basic Y2xpZW50OnNlY3JldA==",
	)
	assert.Equal(t, http.StatusOK, w.Code, "a Range request must not become an unverified 206")
	assert.Equal(t, e.fake.blob, w.Body.Bytes())
	assert.Equal(t, "identity", e.fake.lastRegistry.Get("Accept-Encoding"))
	assert.Equal(t, "", e.fake.lastRegistry.Get("Range"))
	assert.Equal(t, "", e.fake.lastRegistry.Get("If-None-Match"))
	assert.Equal(t, "Basic tok-1", e.fake.lastRegistry.Get("Authorization"), "the client's credentials never reach ECR")
	assert.Equal(t, "", e.fake.lastS3.Get("Range"))

	// The cache does not vary on the client's encoding.
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, cacheResultHit, w.Header().Get("X-Cachew-Result"))
}

func TestECRPropagatesMissingRepositoriesWithoutCaching(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.missingRepo = true })
	path := "/v2/" + testECRName + "/blobs/" + testDigest(e.fake.blob)

	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, path).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, path).Code)
	registry, _ := e.fake.counts()
	assert.Equal(t, 2, registry, "a 404 is not cached, so a later manifest pull that creates the repository is seen")
}

func TestECRRefusesBodiesItCannotTruncate(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.chunked = true })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusBadGateway, w.Code)

	e = setupECRTest(t, func(f *fakeECR) { f.blob = nil })
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/sha256:"+emptySHA256)
	assert.Equal(t, http.StatusOK, w.Code, "an empty blob is valid when the digest is the empty digest")
	w = e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest([]byte("not-empty")))
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestECRErrorsNeverEchoPresignedURLs(t *testing.T) {
	e := setupECRTest(t, func(f *fakeECR) { f.insecureS3 = true })
	w := e.do(http.MethodGet, "/v2/"+testECRName+"/blobs/"+testDigest(e.fake.blob))
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "fetch from ECR failed: ")
	assert.Contains(t, w.Body.String(), "redirect is not https")
	assert.NotContains(t, w.Body.String(), "%s")
	assert.NotContains(t, w.Body.String(), "presigned-secret")
	assert.NotContains(t, w.Body.String(), "X-Amz-Signature")
	_, s3 := e.fake.counts()
	assert.Equal(t, 0, s3, "a plain-http redirect is never followed")
}

func TestECRKeepsManifestsShortAndBlobsLong(t *testing.T) {
	e := setupECRTest(t, func(*fakeECR) {})
	assert.Equal(t, defaultECRManifestTTL, e.ecr.ttl(ecrManifests))
	assert.Equal(t, time.Duration(0), e.ecr.ttl(ecrBlobs), "zero means the cache maximum")

	config := ecrConfigWithDefaults(ECRConfig{})
	assert.Equal(t, 72*time.Hour, config.ManifestTTL)
	assert.Equal(t, 15*time.Second, config.CredentialTimeout)
	assert.Equal(t, 60*time.Second, config.OriginHeaderTimeout)
}

func TestECRRejectsBadConfig(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/cachew-ecr-read"
	repos := []string{"ecr-public/"}
	for _, config := range []ECRConfig{
		{Registry: "ghcr.io", RoleARN: role, Repositories: repos},
		{Registry: "public.ecr.aws", RoleARN: role, Repositories: repos},
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", RoleARN: role, Repositories: repos},
		{Registry: testECRRegistry + "/path", RoleARN: role, Repositories: repos},
		{Registry: testECRRegistry, Repositories: repos},
		{Registry: testECRRegistry, RoleARN: role},
		{Registry: testECRRegistry, RoleARN: role, Repositories: []string{"/"}},
		{Registry: testECRRegistry, RoleARN: role, Repositories: []string{"Upper/"}},
		{Registry: testECRRegistry, RoleARN: role, Repositories: repos, ManifestTTL: -time.Hour},
	} {
		_, err := validateECRConfig(config)
		assert.Error(t, err, "%+v", config)
	}
	region, err := validateECRConfig(ECRConfig{Registry: testECRRegistry, RoleARN: role, Repositories: repos})
	assert.NoError(t, err)
	assert.Equal(t, "us-east-1", region)
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
