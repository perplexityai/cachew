package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
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
	"github.com/block/cachew/internal/spool"
	"github.com/block/cachew/internal/strategy/handler"
)

const (
	ecrSchemeHTTPS = "https"
	ecrUserAgent   = "cachew-ecr"

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
func RegisterECR(r *Registry, spools spool.Provider) {
	Register(r, "ecr", "Read-only, digest-addressed proxy for an Amazon ECR registry, including its pull-through cache repositories.",
		func(ctx context.Context, config ECRConfig, c cache.Cache, mux Mux) (*ECR, error) {
			registry, err := spools()
			if err != nil {
				return nil, errors.Wrap(err, "create spool registry")
			}
			return NewECR(ctx, config, c, mux, registry)
		})
}

// ECRConfig configures one registry. In HCL:
//
//	ecr "123456789012.dkr.ecr.us-east-1.amazonaws.com" {
//	  role-arn = "arn:aws:iam::123456789012:role/cachew-ecr-read"
//	}
//
// mounts the registry at /v2/ and under /<registry>/v2/. Only manifests and
// blobs addressed by sha256 digest are served; tags are mutable and ECR already
// re-syncs them with pull-through upstreams, so clients resolve tags at ECR.
// One ecr block can own /v2/; the others set prefix-only.
type ECRConfig struct {
	Registry            string        `hcl:"registry,label" help:"The ECR registry host, <account>.dkr.ecr.<region>.amazonaws.com."`
	RoleARN             string        `hcl:"role-arn" help:"The read-only IAM role to assume for ECR pulls."`
	Repositories        []string      `hcl:"repositories,optional" help:"Repository names clients may read, as defense in depth on top of the role's IAM scope: an entry ending in / is a prefix, any other entry is one repository. Empty serves every repository the role can read."`
	ManifestTTL         time.Duration `hcl:"manifest-ttl,optional" default:"72h" help:"How long a cached manifest is served. Keep it to days: cache hits never reach ECR, so lastRecordedPullTime goes stale and sinceImagePulled lifecycle rules could expire images still in use. Zero uses the default."`
	CredentialTimeout   time.Duration `hcl:"credential-timeout,optional" default:"15s" help:"Maximum time to wait for ECR credential refresh, including a concurrent refresh. Zero uses the default."`
	OriginHeaderTimeout time.Duration `hcl:"origin-header-timeout,optional" default:"60s" help:"Maximum time to wait for ECR response headers. A first pull through a pull-through rule imports the image before answering. Zero uses the default."`
	PrefixOnly          bool          `hcl:"prefix-only,optional" help:"Mount only under /<registry>/v2/. One ecr block can own the host root's /v2/; set this on the others."`
}

// The ECR [Strategy] serves manifests from cache and hands blobs back to S3.
// Manifest misses authenticate with a GetAuthorizationToken token from an
// assumed role; the body is hashed while it streams, and a digest mismatch
// aborts the cache write and truncates the response. A blob GET answers with
// ECR's redirect to a presigned S3 URL and a blob HEAD with ECR's metadata, so
// layers never stream through the proxy.
type ECR struct {
	registry     string
	repositories []string
	manifestTTL  time.Duration
	tokens       codeArtifactTokenSource
	client       *http.Client // manifests: follows redirects over https
	blobClient   *http.Client // blobs: returns ECR's redirect unfollowed
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
	errECRRejected    = errors.New("ECR rejected the proxy's token (expired credentials, or a repository outside the role's scope)")
	errECRTransport   = errors.New("ecr transport")
	errECRRefresh     = errors.New("could not refresh ECR authorization")
)

// ecrRouteTaken reports whether mux already routes path to a handler mounted
// at or below it, so a duplicate ecr block is a configuration error rather
// than a ServeMux panic. A catch-all route above path does not count.
func ecrRouteTaken(mux Mux, path string) bool {
	_, pattern := mux.Handler(&http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}})
	return strings.HasPrefix(strings.TrimPrefix(pattern, http.MethodGet+" "), path)
}

type ecrAuthorizationClient interface {
	GetAuthorizationToken(
		context.Context,
		*awsecr.GetAuthorizationTokenInput,
		...func(*awsecr.Options),
	) (*awsecr.GetAuthorizationTokenOutput, error)
}

// NewECR creates the strategy for one registry and mounts it on mux.
func NewECR(ctx context.Context, config ECRConfig, c cache.Cache, mux Mux, spools *spool.Registry) (*ECR, error) {
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
	return newECR(config, tokens, base, c, mux, spools)
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

func newECR(config ECRConfig, tokens codeArtifactTokenSource, base http.RoundTripper, c cache.Cache, mux Mux, spools *spool.Registry) (*ECR, error) {
	if ecrRouteTaken(mux, "/"+config.Registry+"/v2/") {
		return nil, errors.Errorf("ecr %s: configured more than once", config.Registry)
	}
	if !config.PrefixOnly && ecrRouteTaken(mux, "/v2/") {
		return nil, errors.Errorf("ecr %s: /v2/ is already mounted; set prefix-only on all but one ecr block", config.Registry)
	}
	transport := ecrTransport{base: base}
	s := &ECR{
		registry:     config.Registry,
		repositories: config.Repositories,
		manifestTTL:  config.ManifestTTL,
		tokens:       tokens,
		client:       &http.Client{Transport: transport, CheckRedirect: checkHTTPSRedirect},
		blobClient: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cache: c,
		now:   time.Now,
	}
	s.handler = handler.New(s.client, c, spools).
		CacheKey(func(r *http.Request) string {
			ref, err := parseECRPath(r.PathValue("rest"))
			if err != nil {
				// Unreachable: serve below rejects other paths first.
				return ""
			}
			return ECRCacheKey(s.registry, ref.name, ref.digest)
		}).
		Transform(func(r *http.Request) (*http.Request, error) {
			ref, err := parseECRPath(r.PathValue("rest"))
			if err != nil {
				return nil, httputil.Errorf(http.StatusNotFound, "%s", err)
			}
			return s.request(r.Context(), ref, http.MethodGet)
		}).
		TTL(func(*http.Request) time.Duration { return s.manifestTTL }).
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
		if ref.kind == ecrBlobs {
			s.serveBlob(w, r, ref)
			return
		}
		// The upstream fetch is always identity-encoded, so the handler must
		// not vary the cache key on what the client would have accepted.
		r.Header.Del("Accept-Encoding")
		// Manifests are served whole. On a miss the handler cuts ranges from the
		// fill as it streams, so a range could complete before the digest is
		// checked at the end of the body.
		r.Header.Del("Range")
		r.Header.Del("If-Range")
		if r.Method == http.MethodHead {
			s.serveManifestHead(w, r, ref)
			return
		}
		s.handler.ServeHTTP(&hideExpiry{ResponseWriter: w}, r)
	})
	// GET patterns also match HEAD. Clients such as go-containerregistry, Helm
	// and Docker want the registry at the host root; containerd mirrors can use
	// the prefix through override_path.
	if !config.PrefixOnly {
		mux.Handle("GET /v2/{rest...}", serve)
	}
	mux.Handle("GET /"+config.Registry+"/v2/{rest...}", serve)
	return s, nil
}

// serveBlob hands blob bytes back to S3. A GET answers with ECR's redirect to a
// presigned S3 URL, which grants that one blob for a short time; a HEAD answers
// with ECR's own length and digest. Clients verify blob digests themselves, and
// Range and resumed downloads work against S3. Nothing is cached: the redirect
// expires, and a blob pull needs ECR and S3 to be reachable.
func (s *ECR) serveBlob(w http.ResponseWriter, r *http.Request, ref ecrRef) {
	req, err := s.request(r.Context(), ref, r.Method)
	if err != nil {
		writeECRError(err, w, r)
		return
	}
	resp, err := s.blobClient.Do(req)
	if err != nil {
		writeECRError(err, w, r)
		return
	}
	defer func() {
		// Drain a little so the connection to ECR can be reused.
		io.CopyN(io.Discard, resp.Body, 2048) //nolint:errcheck,gosec // best effort
		_ = resp.Body.Close()
	}()
	switch {
	case r.Method == http.MethodGet && resp.StatusCode == http.StatusTemporaryRedirect:
		raw := resp.Header.Get("Location")
		location, err := url.Parse(raw)
		if err != nil || location.Scheme != ecrSchemeHTTPS || location.Host == "" {
			s.blobFailure(w, r, "ECR blob redirect is not an absolute https URL", resp.StatusCode)
			return
		}
		// Copied verbatim: re-serializing could change the signed URL.
		w.Header().Set("Location", raw)
		// The presigned URL expires; it must not outlive it in any client cache.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusTemporaryRedirect)
	case r.Method == http.MethodHead && resp.StatusCode == http.StatusOK:
		if digest := resp.Header.Get("Docker-Content-Digest"); digest != ref.digest {
			s.blobFailure(w, r, "ECR reported a different digest for the blob", resp.StatusCode)
			return
		}
		if resp.ContentLength < 0 {
			s.blobFailure(w, r, "ECR blob HEAD has no Content-Length", resp.StatusCode)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		w.Header().Set("Docker-Content-Digest", ref.digest)
		w.WriteHeader(http.StatusOK)
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusTooManyRequests:
		// Kept, as for manifests: a 404 lets mirror clients fall back to the
		// next host, and a 429 tells them to back off.
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		http.Error(w, http.StatusText(resp.StatusCode), resp.StatusCode)
	default:
		s.blobFailure(w, r, "unexpected ECR blob response", resp.StatusCode)
	}
}

// blobFailure logs the upstream status and answers 502. It never logs or echoes
// the Location, which carries a presigned credential.
func (s *ECR) blobFailure(w http.ResponseWriter, r *http.Request, reason string, status int) {
	logging.FromContext(r.Context()).ErrorContext(r.Context(), reason, "registry", s.registry, "method", r.Method, "status", status)
	http.Error(w, reason, http.StatusBadGateway)
}

// serveManifestHead answers a manifest HEAD from the cache entry's metadata. On
// a miss it first fills the cache with a verified GET, so a HEAD never vouches
// for a digest whose bytes have not been checked; manifests are small, and the
// fill also performs a pull-through repository's first import.
func (s *ECR) serveManifestHead(w http.ResponseWriter, r *http.Request, ref ecrRef) {
	key := cache.NewKey(ECRCacheKey(s.registry, ref.name, ref.digest))
	options := httputil.ConditionalOptions(r)
	headers, err := s.cache.Stat(r.Context(), key, options...)
	result := handler.CacheResultHit
	if errors.Is(err, os.ErrNotExist) {
		fill := &statusRecorder{header: http.Header{}}
		get := r.Clone(r.Context())
		get.Method = http.MethodGet
		for _, name := range []string{"Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
			get.Header.Del(name)
		}
		s.fillManifest(fill, get)
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
		result = handler.CacheResultMiss
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

// fillManifest runs the GET a manifest HEAD miss uses to fill the cache. A
// shared fill that fails after its response started aborts the handler; the
// recorder is then left incomplete, which the caller reports as a bad gateway.
func (s *ECR) fillManifest(w *statusRecorder, r *http.Request) {
	defer func() {
		if v := recover(); v != nil {
			if err, ok := v.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
				panic(v)
			}
		}
	}()
	s.handler.ServeHTTP(w, r)
}

// statusRecorder discards a body and keeps the status and length, for the GET
// a manifest HEAD miss runs to fill the cache.
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

// allowed reports whether a client may read the repository. The role's IAM
// scope is the boundary; a configured list narrows it further.
func (s *ECR) allowed(name string) bool {
	if len(s.repositories) == 0 {
		return true
	}
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

// writeECRError answers with the error's status but never a URL: http.Client
// wraps fetch failures in a url.Error naming the request URL, and its own
// errors can quote a raw Location, which may be a presigned S3 URL. Only this
// strategy's errors, which name hosts alone, are echoed.
func writeECRError(err error, w http.ResponseWriter, r *http.Request) {
	for _, logged := range []error{errECRRejected, errECRRefresh} {
		if errors.Is(err, logged) {
			// The transport already logged it with its detail.
			http.Error(w, logged.Error(), http.StatusBadGateway)
			return
		}
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		msg := "fetch from ECR failed"
		if ecrOwnError(urlErr.Err) {
			msg = fmt.Sprintf("%s: %s", msg, urlErr.Err)
		}
		httputil.ErrorResponse(w, r, http.StatusBadGateway, msg)
		return
	}
	if responder, ok := errors.AsType[httputil.HTTPResponder](err); ok {
		responder.WriteHTTP(w, r)
		return
	}
	httputil.ErrorResponse(w, r, http.StatusInternalServerError, err.Error())
}

func ecrOwnError(err error) bool {
	for _, own := range []error{errTooManyHops, errInsecureHop, errDigestFailed, errNoLength, errPartial, errECRTransport} {
		if errors.Is(err, own) {
			return true
		}
	}
	return false
}

// ECRCacheKey names a manifest in the cache. The spaces keep it disjoint from
// the URL-shaped keys other strategies write into the same namespace.
func ECRCacheKey(registry, name, digest string) string {
	return "ecr manifest " + registry + " " + name + " " + digest
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

// request returns the upstream request for ref. Its context carries the token
// and expected digest for ecrTransport, which builds every header, sends the
// token to the registry only, and verifies manifest bytes.
func (s *ECR) request(ctx context.Context, ref ecrRef, method string) (*http.Request, error) {
	token, err := s.tokens.Token(ctx, 0)
	if err != nil {
		// AWS errors name the role and account; log them, answer with the status.
		logging.FromContext(ctx).ErrorContext(ctx, "Failed to obtain ECR authorization", "error", err)
		return nil, httputil.Errorf(http.StatusBadGateway, "could not obtain ECR authorization")
	}
	fetch := &ecrFetch{registry: s.registry, repository: ref.name, digest: ref.digest, token: token, strategy: s}
	if ref.kind == ecrManifests {
		fetch.accept = ecrManifestAccept
		fetch.expiresAt = s.now().Add(s.manifestTTL)
	} else {
		fetch.passthrough = true
	}
	target := ecrSchemeHTTPS + "://" + s.registry + "/v2/" + ref.name + "/" + ref.kind + "/" + ref.digest
	req, err := http.NewRequestWithContext(context.WithValue(ctx, ecrFetchKey{}, fetch), method, target, nil)
	if err != nil {
		return nil, httputil.Errorf(http.StatusInternalServerError, "create ECR request: %w", err)
	}
	return req, nil
}

func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errTooManyHops
	}
	if req.URL.Scheme != ecrSchemeHTTPS {
		return errors.Wrapf(errInsecureHop, "%s://%s", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// ecrFetch is shared by every hop of one fetch, so a token refreshed on the
// registry hop is the one a retry uses.
type ecrFetch struct {
	registry    string
	repository  string
	digest      string
	accept      string
	token       codeArtifactToken
	strategy    *ECR
	retried     bool
	passthrough bool      // blobs: serveBlob reads the status and headers
	expiresAt   time.Time // zero for blobs
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

// ecrTransport builds every header that reaches ECR from scratch. The shared
// handler and http.Client's redirects copy the client's headers onto upstream
// requests, and S3 rejects a presigned URL with any unsigned X-Amz-* header, so
// none of them pass: only Accept for manifests, Accept-Encoding pinned to
// identity (the digest is over the stored bytes), a fixed User-Agent, and
// ECR's credentials on the registry hop only.
type ecrTransport struct {
	base http.RoundTripper
}

func (t ecrTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fetch, isFetch := req.Context().Value(ecrFetchKey{}).(*ecrFetch)
	req = req.Clone(req.Context())
	req.Header = http.Header{"Accept-Encoding": {"identity"}, "User-Agent": {ecrUserAgent}}
	if !isFetch {
		return t.roundTrip(req)
	}
	if fetch.accept != "" {
		req.Header.Set("Accept", fetch.accept)
	}
	registryHop := req.URL.Host == fetch.registry
	if registryHop {
		req.Header.Set("Authorization", "Basic "+fetch.token.value)
	}
	resp, err := t.roundTrip(req)
	if err != nil {
		return nil, err
	}
	if registryHop && ecrRejected(resp) && !fetch.retried {
		if resp, err = t.retryRejected(req, resp, fetch); err != nil {
			return nil, err
		}
	}
	if registryHop && ecrRejected(resp) {
		// The proxy's token or its role's scope is the cause, never the client's
		// credentials (clients send none), so a 401 would read to them as a login
		// problem on their side. Without repositories set, any client can cause
		// one by naming a repository outside the role's scope, so only an
		// allowlisted deployment, where that cannot happen, logs it as an error.
		_ = resp.Body.Close()
		level := slog.LevelWarn
		if len(fetch.strategy.repositories) > 0 {
			level = slog.LevelError
		}
		logging.FromContext(req.Context()).Log(req.Context(), level, errECRRejected.Error(),
			"registry", fetch.registry, "repository", fetch.repository, "status", resp.StatusCode)
		return nil, errors.Wrapf(errECRRejected, "status %d", resp.StatusCode)
	}
	if fetch.passthrough {
		return resp, nil
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400 && registryHop:
		// A redirect; http.Client follows it over https only.
		return resp, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.StatusCode != http.StatusOK:
		_ = resp.Body.Close()
		return nil, errors.Wrapf(errPartial, "%s returned %d", req.URL.Host, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return withoutUpstreamDetail(req.Context(), req.URL.Host, resp), nil
	}
	return verifyECRResponse(req, resp, fetch)
}

func ecrRejected(resp *http.Response) bool {
	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
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
		return nil, errECRRefresh
	}
	if refreshed.generation == fetch.token.generation {
		return resp, nil
	}
	_ = resp.Body.Close()
	fetch.token = refreshed
	req.Header.Set("Authorization", "Basic "+refreshed.value)
	return t.roundTrip(req)
}

// verifyECRResponse wraps a manifest body in the digest verifier and sets the
// headers this strategy owns. Errors name the host only: the path can carry
// the registry's account.
func verifyECRResponse(req *http.Request, resp *http.Response, fetch *ecrFetch) (*http.Response, error) {
	expected := strings.TrimPrefix(fetch.digest, "sha256:")
	switch {
	case resp.ContentLength < 0:
		_ = resp.Body.Close()
		return nil, errors.Wrapf(errNoLength, "%s", req.URL.Host)
	case resp.ContentLength == 0 && expected != emptySHA256:
		_ = resp.Body.Close()
		return nil, errors.Wrapf(errDigestFailed, "%s returned an empty body for sha256:%s", req.URL.Host, expected)
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
	retryAfter := resp.Header.Get("Retry-After")
	resp.Header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	if retryAfter != "" {
		resp.Header.Set("Retry-After", retryAfter)
	}
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp
}

func (t ecrTransport) roundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req) //nolint:bodyclose // the caller owns resp.Body
	if err != nil {
		// Name the host only: presigned S3 URLs carry credentials.
		return nil, errors.Errorf("%w: %s: %w", errECRTransport, req.URL.Host, err)
	}
	return resp, nil
}

// digestVerifyingBody hashes the upstream body as it streams and withholds the
// final digestHoldback bytes until EOF confirms the digest. A mismatch is
// returned as a read error with those bytes still unsent, so the handler
// aborts the cache entry and the client sees a truncated response rather than
// a complete wrong one. That truncation relies on the upstream Content-Length
// the handler copied to the client; ECR sends it.
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
	// Shift in place so the next append reuses the buffer instead of growing it.
	b.held = append(b.held[:0], b.held[n:]...)
	if b.verified && len(b.held) == 0 {
		return n, io.EOF
	}
	return n, nil
}
