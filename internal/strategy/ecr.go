package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/handler"
)

const (
	httpsScheme = "https"

	defaultECRManifestTTL       = 72 * time.Hour
	defaultECRCredentialTimeout = 15 * time.Second
	defaultECROriginTimeout     = 60 * time.Second

	// A rejected token is refreshed at most this often. ECR answers 403 both for
	// an expired token and for a repository the role cannot read, and only the
	// first is fixed by a new token; without a limit every denied request would
	// mint one.
	ecrForcedRefreshInterval = time.Minute

	ecrManifests = "manifests"
	ecrBlobs     = "blobs"

	// Values of handler.CacheResultHeader.
	cacheResultHit  = "hit"
	cacheResultMiss = "miss"

	// Every manifest type a digest can name, so ECR returns the stored bytes
	// rather than negotiating a conversion that would not match the digest.
	ecrManifestAccept = "application/vnd.oci.image.index.v1+json, " +
		"application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, " +
		"application/vnd.docker.distribution.manifest.v2+json"

	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Bytes withheld from the client until the digest verifies, so a mismatch
	// leaves the response short of its Content-Length and the server closes the
	// connection instead of completing a wrong body. That only holds when the
	// upstream declared a length, so ecrTransport rejects 200 responses without
	// one: a chunked body could be terminated cleanly after wrong bytes.
	digestHoldback = 4096
)

// RegisterECR adds the ecr strategy to the registry.
func RegisterECR(r *Registry) {
	Register(r, "ecr", "Read-only, digest-addressed proxy for an Amazon ECR registry, including its pull-through cache repositories.", NewECR)
}

// ECRConfig configures one registry. In HCL:
//
//	ecr "123456789012.dkr.ecr.us-east-1.amazonaws.com" {
//	  role-arn     = "arn:aws:iam::123456789012:role/cachew-ecr-read"
//	  repositories = ["ecr-public/buildkite/"]
//	}
//
// mounts the registry at /v2/ and under /<registry>/v2/. Only manifests and
// blobs addressed by sha256 digest are served; tags are mutable and ECR already
// re-syncs them with pull-through upstreams, so clients resolve tags at ECR.
// One ecr block can own /v2/; the others set prefix-only.
type ECRConfig struct {
	Registry            string        `hcl:"registry,label" help:"The ECR registry host, <account>.dkr.ecr.<region>.amazonaws.com."`
	RoleARN             string        `hcl:"role-arn" help:"The read-only IAM role to assume for ECR pulls."`
	Repositories        []string      `hcl:"repositories" help:"Repository names clients may read: an entry ending in / is a prefix, any other entry is one repository. Required; scope the role to the same repositories, since clients are unauthenticated."`
	ManifestTTL         time.Duration `hcl:"manifest-ttl,optional" default:"72h" help:"How long a cached manifest is served. Keep it to days: cache hits never reach ECR, so lastRecordedPullTime goes stale and sinceImagePulled lifecycle rules could expire images still in use. Zero uses the default."`
	CredentialTimeout   time.Duration `hcl:"credential-timeout,optional" default:"15s" help:"Maximum time to wait for ECR credential refresh, including a concurrent refresh. Zero uses the default."`
	OriginHeaderTimeout time.Duration `hcl:"origin-header-timeout,optional" default:"60s" help:"Maximum time to wait for ECR or S3 response headers. A first pull through a pull-through rule imports the image before answering. Zero uses the default."`
	PrefixOnly          bool          `hcl:"prefix-only,optional" help:"Mount only under /<registry>/v2/. One ecr block can own the host root's /v2/; set this on the others."`
}

// The ECR [Strategy] serves GET and HEAD for /v2/<name>/manifests/<digest> and
// /v2/<name>/blobs/<digest> from cache. Misses authenticate with a
// GetAuthorizationToken token from an assumed role and follow ECR's signed
// redirect to S3 for blobs. The body is hashed while it streams; a digest
// mismatch aborts the cache write and truncates the response.
type ECR struct {
	registry     string
	repositories []string
	manifestTTL  time.Duration
	tokens       codeArtifactTokenSource
	client       *http.Client
	cache        cache.Cache
	handler      *handler.Handler
	now          func() time.Time
	// lastForcedRefresh is the UnixNano time of the last refresh a rejection
	// triggered; see ecrForcedRefreshInterval.
	lastForcedRefresh atomic.Int64
}

var _ Strategy = (*ECR)(nil)

var (
	// Repository names follow the OCI distribution grammar: lowercase
	// alphanumerics joined by one period, one or two underscores, or dashes.
	ecrPath           = regexp.MustCompile(`^([a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)/(manifests|blobs)/(sha256:[0-9a-f]{64})$`)
	ecrRegistryHost   = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$`)
	ecrRepositoryName = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	errECRNotDigest   = errors.New("not a manifest or blob digest path")
	errTooManyHops    = errors.New("too many redirects")
	errInsecureHop    = errors.New("redirect is not https")
	errDigestFailed   = errors.New("digest mismatch")
	errNoLength       = errors.New("registry response has no Content-Length")
	errPartial        = errors.New("registry returned a 2xx other than 200")
)

type ecrAuthorizationClient interface {
	GetAuthorizationToken(
		context.Context,
		*awsecr.GetAuthorizationTokenInput,
		...func(*awsecr.Options),
	) (*awsecr.GetAuthorizationTokenOutput, error)
}

// NewECR creates the strategy for one registry and mounts it on mux.
func NewECR(ctx context.Context, config ECRConfig, c cache.Cache, mux Mux) (*ECR, error) {
	config = ecrConfigWithDefaults(config)
	region, err := validateECRConfig(config)
	if err != nil {
		return nil, err
	}
	client, err := newECRClient(ctx, region, config)
	if err != nil {
		return nil, err
	}
	tokens := newOriginTokenManager("ECR", config.CredentialTimeout, ecrTokenMinter(client), time.Now)
	base := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the default is always *http.Transport
	base.DisableCompression = true
	base.ResponseHeaderTimeout = config.OriginHeaderTimeout
	return newECR(config, tokens, base, c, mux)
}

func ecrConfigWithDefaults(config ECRConfig) ECRConfig {
	if config.ManifestTTL == 0 {
		config.ManifestTTL = defaultECRManifestTTL
	}
	if config.CredentialTimeout == 0 {
		config.CredentialTimeout = defaultECRCredentialTimeout
	}
	if config.OriginHeaderTimeout == 0 {
		config.OriginHeaderTimeout = defaultECROriginTimeout
	}
	return config
}

// validateECRConfig returns the registry's region.
func validateECRConfig(config ECRConfig) (string, error) {
	m := ecrRegistryHost.FindStringSubmatch(config.Registry)
	if m == nil {
		return "", errors.Errorf("ecr: registry must be <account>.dkr.ecr.<region>.amazonaws.com, got %q", config.Registry)
	}
	if !strings.HasPrefix(config.RoleARN, "arn:") {
		return "", errors.Errorf("ecr %s: role-arn must be an IAM role ARN", config.Registry)
	}
	if len(config.Repositories) == 0 {
		return "", errors.Errorf("ecr %s: repositories must list at least one repository or prefix", config.Registry)
	}
	for _, repository := range config.Repositories {
		if !ecrRepositoryName.MatchString(strings.TrimSuffix(repository, "/")) {
			return "", errors.Errorf("ecr %s: repositories entry %q is not a repository name or a prefix ending in /", config.Registry, repository)
		}
	}
	if config.ManifestTTL < 0 || config.CredentialTimeout < 0 || config.OriginHeaderTimeout < 0 {
		return "", errors.Errorf("ecr %s: manifest-ttl, credential-timeout and origin-header-timeout must not be negative", config.Registry)
	}
	return m[1], nil
}

func newECRClient(ctx context.Context, region string, config ECRConfig) (*awsecr.Client, error) {
	loadCtx, cancel := context.WithTimeout(ctx, config.CredentialTimeout)
	defer cancel()
	awsConfig, err := awsconfig.LoadDefaultConfig(loadCtx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, errors.Wrap(err, "load AWS configuration for ECR")
	}
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsConfig), config.RoleARN)
	awsConfig.Credentials = aws.NewCredentialsCache(provider)
	return awsecr.NewFromConfig(awsConfig), nil
}

// ecrTokenMinter mints the base64 "AWS:<password>" token ECR accepts as Basic
// credentials. It is valid for every registry the role can read, for 12 hours.
func ecrTokenMinter(client ecrAuthorizationClient) originTokenMinter {
	return func(ctx context.Context) (string, time.Time, error) {
		output, err := client.GetAuthorizationToken(ctx, &awsecr.GetAuthorizationTokenInput{})
		if err != nil {
			return "", time.Time{}, err //nolint:wrapcheck // refreshToken wraps mint errors with the origin name.
		}
		if len(output.AuthorizationData) != 1 {
			return "", time.Time{}, nil
		}
		data := output.AuthorizationData[0]
		return aws.ToString(data.AuthorizationToken), aws.ToTime(data.ExpiresAt), nil
	}
}

func newECR(config ECRConfig, tokens codeArtifactTokenSource, base http.RoundTripper, c cache.Cache, mux Mux) (*ECR, error) {
	s := &ECR{
		registry:     config.Registry,
		repositories: config.Repositories,
		manifestTTL:  config.ManifestTTL,
		tokens:       tokens,
		client: &http.Client{
			Transport:     ecrTransport{base: base},
			CheckRedirect: checkHTTPSRedirect,
		},
		cache: c,
		now:   time.Now,
	}
	s.handler = handler.New(s.client, c).
		CacheKey(func(r *http.Request) string {
			ref, err := parseECRPath(r.PathValue("rest"))
			if err != nil {
				// Unreachable: serve below rejects other paths first.
				return ""
			}
			return ECRCacheKey(s.registry, ref.kind, ref.name, ref.digest)
		}).
		Transform(func(r *http.Request) (*http.Request, error) {
			ref, err := parseECRPath(r.PathValue("rest"))
			if err != nil {
				return nil, httputil.Errorf(http.StatusNotFound, "%s", err)
			}
			return s.request(r.Context(), ref)
		}).
		TTL(func(r *http.Request) time.Duration {
			ref, err := parseECRPath(r.PathValue("rest"))
			if err != nil {
				return 0
			}
			return s.ttl(ref.kind)
		}).
		OnError(writeECRError)
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := r.PathValue("rest")
		if rest == "" {
			servePing(w, r)
			return
		}
		// Reject anything but a digest path before the cache is consulted, so an
		// entry another strategy wrote under a similar key can never be served here.
		ref, err := parseECRPath(rest)
		if err != nil {
			http.Error(w, err.Error()+": only /v2/<name>/manifests/sha256:<digest> and /v2/<name>/blobs/sha256:<digest> are served", http.StatusNotFound)
			return
		}
		if !s.allowed(ref.name) {
			http.Error(w, "repository is not served by this proxy", http.StatusNotFound)
			return
		}
		// The upstream fetch is always identity-encoded, so the handler must
		// not vary the cache key on what the client would have accepted.
		r.Header.Del("Accept-Encoding")
		if r.Method == http.MethodHead {
			s.serveHead(w, r, ref)
			return
		}
		s.handler.ServeHTTP(&hideExpiry{ResponseWriter: w}, r)
	})
	// GET patterns also match HEAD. Clients such as go-containerregistry, Helm
	// and Docker want the registry at the host root; containerd mirrors can use
	// the prefix through override_path.
	// The root goes first: if another ecr block owns it, nothing is mounted.
	var patterns []string
	if !config.PrefixOnly {
		patterns = append(patterns, "GET /v2/{rest...}")
	}
	patterns = append(patterns, "GET /"+config.Registry+"/v2/{rest...}")
	if err := mountECR(mux, patterns, serve); err != nil {
		return nil, errors.Wrapf(err, "ecr %s", config.Registry)
	}
	return s, nil
}

// mountECR turns ServeMux's panic on a duplicate pattern, such as a second
// ecr block without prefix-only, into a configuration error.
func mountECR(mux Mux, patterns []string, h http.Handler) (err error) {
	defer func() {
		if conflict := recover(); conflict != nil {
			err = errors.Errorf("conflicting routes (only one ecr block can omit prefix-only): %v", conflict)
		}
	}()
	for _, pattern := range patterns {
		mux.Handle(pattern, h)
	}
	return nil
}

// serveHead answers HEAD from the cache entry's metadata. On a miss it first
// fills the cache with a verified GET, so a HEAD never vouches for a digest
// whose bytes have not been checked; for blobs that means a HEAD downloads the
// blob once.
func (s *ECR) serveHead(w http.ResponseWriter, r *http.Request, ref ecrRef) {
	key := cache.NewKey(ECRCacheKey(s.registry, ref.kind, ref.name, ref.digest))
	options := httputil.ConditionalOptions(r)
	headers, err := s.cache.Stat(r.Context(), key, options...)
	result := cacheResultHit
	if errors.Is(err, os.ErrNotExist) {
		fill := &statusRecorder{header: http.Header{}}
		get := r.Clone(r.Context())
		get.Method = http.MethodGet
		for _, name := range []string{"Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
			get.Header.Del(name)
		}
		s.handler.ServeHTTP(fill, get)
		// Zero means nothing was written: verification failed before any bytes
		// were released, and the Stat below finds no entry.
		if fill.status != 0 && fill.status != http.StatusOK {
			w.WriteHeader(fill.status)
			return
		}
		headers, err = s.cache.Stat(r.Context(), key, options...)
		if errors.Is(err, os.ErrNotExist) {
			if !fill.complete() {
				// The fill was cut short: the bytes did not match the digest.
				httputil.ErrorResponse(w, r, http.StatusBadGateway, "ECR returned bytes that do not match "+ref.digest)
				return
			}
			// Verified, but the cache did not keep it (for example, over its size limit).
			headers, err = fill.header, nil
		}
		result = cacheResultMiss
	}
	headers = headers.Clone()
	headers.Del(handler.CacheResultHeader)
	headers.Del(cache.ExpirationKey)
	w.Header().Set(handler.CacheResultHeader, result)
	if !httputil.ServeCacheStat(w, headers, err) {
		w.Header().Del(handler.CacheResultHeader)
		logging.FromContext(r.Context()).ErrorContext(r.Context(), "Failed to stat ECR cache entry", "error", err)
		http.Error(w, "cache unavailable", http.StatusInternalServerError)
	}
}

// statusRecorder discards a body and keeps the status and length, for the GET
// a HEAD miss runs to fill the cache.
type statusRecorder struct {
	header  http.Header
	status  int
	written int64
}

func (r *statusRecorder) Header() http.Header { return r.header }

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	r.written += int64(len(p))
	return len(p), nil
}

// complete reports whether the whole declared body was written. The digest
// verifier releases the final bytes only after the digest checks, so a complete
// 200 body is a verified one. An empty body is never written, so status stays
// zero; the transport has already refused an empty body for a non-empty digest.
func (r *statusRecorder) complete() bool {
	length, err := strconv.ParseInt(r.header.Get("Content-Length"), 10, 64)
	ok := r.status == http.StatusOK || (r.status == 0 && length == 0)
	return ok && err == nil && r.written == length
}

// hideExpiry keeps the cache's internal expiry header out of client responses.
type hideExpiry struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *hideExpiry) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.Header().Del(cache.ExpirationKey)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *hideExpiry) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p) //nolint:wrapcheck // ResponseWriter callers expect its errors unwrapped.
}

// ReadFrom keeps the server's sendfile path for disk-cache hits.
func (w *hideExpiry) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return io.Copy(w.ResponseWriter, r) //nolint:wrapcheck // ResponseWriter callers expect its errors unwrapped.
}

func (w *hideExpiry) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *ECR) String() string { return "ecr:" + s.registry }

// allowed reports whether a client may read the repository: clients are
// unauthenticated, so this list, not the role, bounds what they reach.
func (s *ECR) allowed(name string) bool {
	for _, repository := range s.repositories {
		if strings.HasSuffix(repository, "/") {
			if strings.HasPrefix(name, repository) {
				return true
			}
		} else if name == repository {
			return true
		}
	}
	return false
}

// writeECRError answers with the error's status but never its URL: http.Client
// wraps fetch failures in a url.Error naming the request URL, and after ECR's
// redirect that is a presigned S3 URL carrying credentials.
func writeECRError(err error, w http.ResponseWriter, r *http.Request) {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		httputil.ErrorResponse(w, r, http.StatusBadGateway, fmt.Sprintf("fetch from ECR failed: %s", urlErr.Err))
		return
	}
	if responder, ok := errors.AsType[httputil.HTTPResponder](err); ok {
		responder.WriteHTTP(w, r)
		return
	}
	httputil.ErrorResponse(w, r, http.StatusInternalServerError, err.Error())
}

// ECRCacheKey names a manifest or blob in the cache. The spaces keep it
// disjoint from the URL-shaped keys other strategies write into the same
// namespace.
func ECRCacheKey(registry, kind, name, digest string) string {
	return "ecr " + registry + " " + kind + " " + name + " " + digest
}

// ttl keeps manifests short: their content never changes, but a cached
// manifest hides pulls from ECR's lifecycle rules. Blobs use the cache maximum.
func (s *ECR) ttl(kind string) time.Duration {
	if kind == ecrManifests {
		return s.manifestTTL
	}
	return 0
}

// servePing answers the distribution API version check without contacting
// ECR, so anonymous clients can discover the registry.
func servePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	if _, err := io.WriteString(w, "{}"); err != nil {
		logging.FromContext(r.Context()).DebugContext(r.Context(), "Failed to write registry version response", "error", err)
	}
}

type ecrRef struct {
	name   string
	kind   string
	digest string
}

func parseECRPath(rest string) (ecrRef, error) {
	m := ecrPath.FindStringSubmatch(rest)
	if m == nil {
		return ecrRef{}, errECRNotDigest
	}
	return ecrRef{name: m[1], kind: m[2], digest: m[3]}, nil
}

// request returns the GET the handler executes. The request context carries the
// token and expected digest for ecrTransport, which authenticates the registry
// hop only and verifies the bytes on the final hop.
func (s *ECR) request(ctx context.Context, ref ecrRef) (*http.Request, error) {
	token, err := s.tokens.Token(ctx, 0)
	if err != nil {
		// AWS errors name the role and account; log them, answer with the status.
		logging.FromContext(ctx).ErrorContext(ctx, "Failed to obtain ECR authorization", "error", err)
		return nil, httputil.Errorf(http.StatusBadGateway, "could not obtain ECR authorization")
	}
	fetch := &ecrFetch{registry: s.registry, digest: ref.digest, token: token, strategy: s}
	if ref.kind == ecrManifests {
		fetch.expiresAt = s.now().Add(s.manifestTTL)
	}
	target := httpsScheme + "://" + s.registry + "/v2/" + ref.name + "/" + ref.kind + "/" + ref.digest
	req, err := http.NewRequestWithContext(context.WithValue(ctx, ecrFetchKey{}, fetch), http.MethodGet, target, nil)
	if err != nil {
		return nil, httputil.Errorf(http.StatusInternalServerError, "create ECR request: %w", err)
	}
	if ref.kind == ecrManifests {
		req.Header.Set("Accept", ecrManifestAccept)
	}
	return req, nil
}

func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errTooManyHops
	}
	if req.URL.Scheme != httpsScheme {
		return errors.Wrapf(errInsecureHop, "%s://%s", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// ecrFetch is shared by every hop of one fetch, so a token refreshed on the
// registry hop is the one a retry uses.
type ecrFetch struct {
	registry  string
	digest    string
	token     codeArtifactToken
	strategy  *ECR
	retried   bool
	expiresAt time.Time // zero for blobs
}

// allowForcedRefresh reports whether a rejection may mint a new token now.
func (s *ECR) allowForcedRefresh() bool {
	now := s.now().UnixNano()
	last := s.lastForcedRefresh.Load()
	if last != 0 && now-last < int64(ecrForcedRefreshInterval) {
		return false
	}
	return s.lastForcedRefresh.CompareAndSwap(last, now)
}

type ecrFetchKey struct{}

// ecrTransport owns every header that reaches ECR and S3. The shared handler
// forwards the client's headers onto the upstream request, so the client's
// Authorization, Range and conditional headers are dropped here and
// Accept-Encoding is pinned to identity: the digest is over the stored bytes,
// not a transfer encoding. ECR's credentials go on the registry hop only;
// http.Client keeps the request context across ECR's redirect to S3, so the
// digest check lands on the final hop.
type ecrTransport struct {
	base http.RoundTripper
}

func (t ecrTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fetch, isFetch := req.Context().Value(ecrFetchKey{}).(*ecrFetch)
	req = req.Clone(req.Context())
	for _, name := range []string{"Authorization", "Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
		req.Header.Del(name)
	}
	req.Header.Set("Accept-Encoding", "identity")
	if !isFetch {
		return t.roundTrip(req)
	}
	registryHop := req.URL.Host == fetch.registry
	if registryHop {
		req.Header.Set("Authorization", "Basic "+fetch.token.value)
	}
	resp, err := t.roundTrip(req)
	if err != nil {
		return nil, err
	}
	rejected := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	if registryHop && rejected && !fetch.retried {
		if resp, err = t.retryRejected(req, resp, fetch); err != nil {
			return nil, err
		}
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && registryHop:
		// ECR's redirect to S3; http.Client follows it.
		return resp, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.StatusCode != http.StatusOK:
		_ = resp.Body.Close()
		return nil, errors.Wrapf(errPartial, "%s returned %d", req.URL.Host, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return withoutUpstreamDetail(req.Context(), req.URL.Host, resp), nil
	}
	return verifyECRResponse(req, resp, fetch)
}

// retryRejected retries a rejected registry request once with a newer token:
// one another request already minted, or, at most once a minute, a new one
// minted for this rejection. A token can be revoked or expire early.
func (t ecrTransport) retryRejected(req *http.Request, resp *http.Response, fetch *ecrFetch) (*http.Response, error) {
	fetch.retried = true
	rejectedGeneration := uint64(0)
	if fetch.strategy.allowForcedRefresh() {
		rejectedGeneration = fetch.token.generation
	}
	refreshed, err := fetch.strategy.tokens.Token(req.Context(), rejectedGeneration)
	if err != nil {
		_ = resp.Body.Close()
		logging.FromContext(req.Context()).ErrorContext(req.Context(), "Failed to refresh ECR authorization", "error", err)
		return nil, errors.New("could not refresh ECR authorization")
	}
	if refreshed.generation == fetch.token.generation {
		return resp, nil
	}
	_ = resp.Body.Close()
	fetch.token = refreshed
	req.Header.Set("Authorization", "Basic "+refreshed.value)
	return t.roundTrip(req)
}

// verifyECRResponse wraps a 200 body in the digest verifier and sets the
// headers this strategy owns.
func verifyECRResponse(req *http.Request, resp *http.Response, fetch *ecrFetch) (*http.Response, error) {
	expected := strings.TrimPrefix(fetch.digest, "sha256:")
	switch {
	case resp.ContentLength < 0:
		_ = resp.Body.Close()
		return nil, errors.Wrapf(errNoLength, "%s%s", req.URL.Host, req.URL.Path)
	case resp.ContentLength == 0 && expected != emptySHA256:
		_ = resp.Body.Close()
		return nil, errors.Wrapf(errDigestFailed, "%s%s returned an empty body for sha256:%s", req.URL.Host, req.URL.Path, expected)
	}
	resp.Body = &digestVerifyingBody{ReadCloser: resp.Body, hash: sha256.New(), expected: expected}
	// ECR sends this on HEAD but not on GET for manifests; clients that verify
	// or resolve by it expect it on both, and the digest is checked as it streams.
	resp.Header.Set("Docker-Content-Digest", fetch.digest)
	// Only this strategy chooses an entry's lifetime; an upstream cannot.
	resp.Header.Del(cache.ExpirationKey)
	if !fetch.expiresAt.IsZero() {
		// Pins the manifest's lifetime through every cache tier: S3 and tiered
		// backfills would otherwise extend it to their maximum TTL.
		resp.Header.Set(cache.ExpirationKey, fetch.expiresAt.UTC().Format(time.RFC3339Nano))
	}
	return resp, nil
}

// withoutUpstreamDetail replaces an error response's body and headers: ECR's
// error bodies name the role, account and session, and NAME_UNKNOWN versus
// MANIFEST_UNKNOWN would let a client probe which repositories exist. The
// status is kept so clients and mirrors can fall back.
func withoutUpstreamDetail(ctx context.Context, host string, resp *http.Response) *http.Response {
	detail, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	logging.FromContext(ctx).DebugContext(ctx, "ECR returned an error",
		"status", resp.StatusCode, "host", host, "body", string(detail), "read_error", readErr)
	body := http.StatusText(resp.StatusCode) + "\n"
	resp.Header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp
}

func (t ecrTransport) roundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req) //nolint:bodyclose // the caller owns resp.Body
	if err != nil {
		// Name the host only: presigned S3 URLs carry credentials.
		return nil, errors.Wrapf(err, "ecr transport: %s", req.URL.Host)
	}
	return resp, nil
}

// digestVerifyingBody hashes the upstream body as it streams and withholds the
// final digestHoldback bytes until EOF confirms the digest. A mismatch is
// returned as a read error with those bytes still unsent, so the handler
// aborts the cache entry and the client sees a truncated response rather than
// a complete wrong one. That truncation relies on the upstream Content-Length
// the handler copied to the client; ECR and S3 send it.
type digestVerifyingBody struct {
	io.ReadCloser
	hash     hash.Hash
	expected string
	held     []byte
	verified bool
	failed   error
}

func (b *digestVerifyingBody) Read(p []byte) (int, error) {
	if b.failed != nil {
		return 0, b.failed
	}
	if len(p) == 0 {
		return 0, nil
	}
	for !b.verified && len(b.held) <= digestHoldback {
		n, err := b.ReadCloser.Read(p)
		if n > 0 {
			_, _ = b.hash.Write(p[:n])
			b.held = append(b.held, p[:n]...)
		}
		if errors.Is(err, io.EOF) {
			if actual := hex.EncodeToString(b.hash.Sum(nil)); actual != b.expected {
				b.held = nil
				b.failed = errors.Wrapf(errDigestFailed, "expected sha256:%s, got sha256:%s", b.expected, actual)
				return 0, b.failed
			}
			b.verified = true
			break
		}
		if err != nil {
			return 0, err //nolint:wrapcheck // Reader callers require unwrapped reader errors.
		}
	}
	release := len(b.held)
	if !b.verified {
		release -= digestHoldback
	}
	n := copy(p, b.held[:release])
	b.held = b.held[n:]
	if b.verified && len(b.held) == 0 {
		return n, io.EOF
	}
	return n, nil
}
