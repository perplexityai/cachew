package strategy

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/strategy/handler"
)

const (
	defaultS3ObjectsOriginHeaderTimeout = 30 * time.Second
	defaultS3ObjectsCredentialTimeout   = 15 * time.Second
	// SHA-256 of an empty payload; every proxied request is a body-less GET.
	s3EmptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	// Dotted bucket names are rejected because they break TLS for virtual-hosted addressing.
	s3BucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	s3RegionRe     = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	s3AccountIDRe  = regexp.MustCompile(`^[0-9]{12}$`)
)

func RegisterS3Objects(r *Registry) {
	Register(r, "s3-objects", "Authenticated read-only proxy for allowlisted S3 object prefixes.", NewS3Objects)
}

// S3ObjectsConfig configures read-only access to allowlisted key prefixes in one S3 bucket.
//
// In HCL it looks something like this:
//
//	s3-objects "example-artifacts" {
//	  region         = "us-east-1"
//	  expected-owner = "111122223333"
//	  prefixes       = ["bazel/archives/"]
//	  role-arn       = "arn:aws:iam::111122223333:role/cachew-example-artifacts-read"
//	}
//
// Objects are served under "/example-artifacts.s3.us-east-1.amazonaws.com/<key>",
// mirroring the virtual-hosted S3 URL so downloader rewrites stay a host-prefix change.
type S3ObjectsConfig struct {
	Bucket              string        `hcl:"bucket,label" help:"The S3 bucket to read objects from."`
	Region              string        `hcl:"region" help:"The AWS region containing the bucket."`
	ExpectedOwner       string        `hcl:"expected-owner" help:"The AWS account ID that must own the bucket."`
	Prefixes            []string      `hcl:"prefixes" help:"Object key prefixes that may be read. Each must be non-empty and end with '/'."`
	RoleARN             string        `hcl:"role-arn,optional" help:"Optional read-only IAM role to assume. Empty uses the service's default AWS credentials."`
	TTL                 time.Duration `hcl:"ttl,optional" help:"Cache TTL for objects. Zero uses the cache's maximum TTL."`
	OriginHeaderTimeout time.Duration `hcl:"origin-header-timeout,optional" default:"30s" help:"Maximum time to wait for S3 response headers. Zero uses the default."`
	CredentialTimeout   time.Duration `hcl:"credential-timeout,optional" default:"15s" help:"Maximum time to wait for AWS credentials. Zero uses the default."`
}

// S3Objects serves allowlisted objects from a single S3 bucket using Cachew's
// own AWS identity, so clients never need S3 credentials.
type S3Objects struct {
	bucket   string
	origin   *url.URL
	prefix   string
	prefixes []string
}

var _ Strategy = (*S3Objects)(nil)

// NewS3Objects creates an S3 object strategy using the default AWS credential chain.
func NewS3Objects(ctx context.Context, config S3ObjectsConfig, objectCache cache.Cache, mux Mux) (*S3Objects, error) {
	config = s3ObjectsConfigWithDefaults(config)
	if err := validateS3ObjectsConfig(config); err != nil {
		return nil, err
	}
	creds, err := newS3ObjectsCredentials(ctx, config)
	if err != nil {
		return nil, err
	}
	origin := &url.URL{Scheme: "https", Host: s3VirtualHost(config.Bucket, config.Region)}
	return newS3Objects(config, objectCache, mux, creds, origin, time.Now)
}

func newS3ObjectsCredentials(ctx context.Context, config S3ObjectsConfig) (aws.CredentialsProvider, error) {
	loadCtx, cancel := context.WithTimeout(ctx, config.CredentialTimeout)
	defer cancel()
	awsConfig, err := awsconfig.LoadDefaultConfig(loadCtx, awsconfig.WithRegion(config.Region))
	if err != nil {
		return nil, errors.Wrap(err, "load AWS configuration for S3 objects")
	}
	if config.RoleARN == "" {
		return awsConfig.Credentials, nil
	}
	return aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsConfig), config.RoleARN)), nil
}

func newS3Objects(
	config S3ObjectsConfig,
	objectCache cache.Cache,
	mux Mux,
	creds aws.CredentialsProvider,
	origin *url.URL,
	now func() time.Time,
) (*S3Objects, error) {
	if err := validateS3ObjectsConfig(config); err != nil {
		return nil, err
	}
	virtualHost := s3VirtualHost(config.Bucket, config.Region)
	s := &S3Objects{
		bucket:   config.Bucket,
		origin:   origin,
		prefix:   "/" + virtualHost,
		prefixes: config.Prefixes,
	}

	base := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck,forcetypeassert
	// Cache the exact bytes S3 stores; Go's transparent gzip would otherwise rewrite bodies and headers.
	base.DisableCompression = true
	base.ResponseHeaderTimeout = config.OriginHeaderTimeout
	client := &http.Client{
		Transport: &s3SigningTransport{
			base:              base,
			signer:            v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }),
			creds:             creds,
			region:            config.Region,
			host:              virtualHost,
			expectedOwner:     config.ExpectedOwner,
			now:               now,
			credentialTimeout: config.CredentialTimeout,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cacheNamespace := objectCache.Namespace(cache.Namespace("s3-objects"))
	hdlr := handler.New(client, cacheNamespace).
		CacheKey(func(r *http.Request) string {
			return s.objectURL(r.PathValue("key")).String()
		}).
		Transform(func(r *http.Request) (*http.Request, error) {
			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.objectURL(r.PathValue("key")).String(), nil)
			if err != nil {
				return nil, errors.Wrap(err, "create S3 request")
			}
			return req, nil
		}).
		TTL(func(_ *http.Request) time.Duration { return config.TTL })

	mux.Handle("GET "+s.prefix+"/{key...}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.admit(r); err != nil {
			httputil.ErrorResponse(w, r, http.StatusNotFound, err.Error())
			return
		}
		hdlr.ServeHTTP(w, r)
	}))
	return s, nil
}

func (s *S3Objects) String() string { return "s3-objects:" + s.bucket }

// admit rejects anything that is not a plain read of an allowlisted key, so
// the proxy cannot be used to list buckets, select versions, or escape a prefix.
func (s *S3Objects) admit(r *http.Request) error {
	if r.URL.RawQuery != "" {
		return errors.New("query strings are not supported")
	}
	key := r.PathValue("key")
	if err := validateS3ObjectKey(key); err != nil {
		return err
	}
	for _, prefix := range s.prefixes {
		if strings.HasPrefix(key, prefix) {
			return nil
		}
	}
	return errors.New("object is not in an allowed prefix")
}

func (s *S3Objects) objectURL(key string) *url.URL {
	u := *s.origin
	u.Path = "/" + key
	u.RawPath = "/" + s3EscapePath(key)
	return &u
}

func validateS3ObjectKey(key string) error {
	if key == "" || len(key) > 1024 {
		return errors.New("invalid object key")
	}
	for _, c := range key {
		if c < 0x20 || c == 0x7f {
			return errors.New("invalid object key")
		}
	}
	for segment := range strings.SplitSeq(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("invalid object key")
		}
	}
	return nil
}

func s3ObjectsConfigWithDefaults(config S3ObjectsConfig) S3ObjectsConfig {
	if config.OriginHeaderTimeout == 0 {
		config.OriginHeaderTimeout = defaultS3ObjectsOriginHeaderTimeout
	}
	if config.CredentialTimeout == 0 {
		config.CredentialTimeout = defaultS3ObjectsCredentialTimeout
	}
	return config
}

func validateS3ObjectsConfig(config S3ObjectsConfig) error {
	if !s3BucketNameRe.MatchString(config.Bucket) || strings.Contains(config.Bucket, "--") {
		return errors.Errorf("s3-objects: invalid bucket name %q", config.Bucket)
	}
	if !s3RegionRe.MatchString(config.Region) {
		return errors.Errorf("s3-objects %s: invalid region %q", config.Bucket, config.Region)
	}
	if !s3AccountIDRe.MatchString(config.ExpectedOwner) {
		return errors.Errorf("s3-objects %s: expected-owner must be a 12-digit AWS account ID", config.Bucket)
	}
	if len(config.Prefixes) == 0 {
		return errors.Errorf("s3-objects %s: at least one prefix is required", config.Bucket)
	}
	for _, prefix := range config.Prefixes {
		if !strings.HasSuffix(prefix, "/") || validateS3ObjectKey(strings.TrimSuffix(prefix, "/")) != nil {
			return errors.Errorf("s3-objects %s: prefix %q must be a non-empty key path ending in '/'", config.Bucket, prefix)
		}
	}
	if config.TTL < 0 || config.OriginHeaderTimeout < 0 || config.CredentialTimeout < 0 {
		return errors.Errorf("s3-objects %s: durations must not be negative", config.Bucket)
	}
	return nil
}

func s3VirtualHost(bucket, region string) string {
	return bucket + ".s3." + region + ".amazonaws.com"
}

// s3EscapePath applies S3's canonical URI encoding to each path segment, so
// the bytes on the wire are exactly the bytes that were signed.
func s3EscapePath(key string) string {
	segments := strings.Split(key, "/")
	for i, segment := range segments {
		var b strings.Builder
		for j := range len(segment) {
			c := segment[j]
			if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') ||
				c == '-' || c == '_' || c == '.' || c == '~' {
				b.WriteByte(c)
				continue
			}
			b.WriteByte('%')
			b.WriteByte("0123456789ABCDEF"[c>>4])
			b.WriteByte("0123456789ABCDEF"[c&0xf])
		}
		segments[i] = b.String()
	}
	return strings.Join(segments, "/")
}

// s3SigningTransport signs outbound S3 requests with Cachew's identity. It
// strips client-controlled credentials and S3 request options so callers can
// neither impersonate another principal nor change how the object is read.
type s3SigningTransport struct {
	base              http.RoundTripper
	signer            *v4.Signer
	creds             aws.CredentialsProvider
	region            string
	host              string
	expectedOwner     string
	now               func() time.Time
	credentialTimeout time.Duration
}

func (t *s3SigningTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	for name := range req.Header {
		if name == "Authorization" || name == "Cookie" || strings.HasPrefix(name, "X-Amz-") {
			req.Header.Del(name)
		}
	}
	req.Host = t.host
	req.Header.Set("X-Amz-Content-Sha256", s3EmptyPayloadHash)
	req.Header.Set("X-Amz-Expected-Bucket-Owner", t.expectedOwner)

	credCtx, cancel := context.WithTimeout(req.Context(), t.credentialTimeout)
	creds, err := t.creds.Retrieve(credCtx)
	cancel()
	if err != nil {
		return nil, errors.Wrap(err, "retrieve AWS credentials for S3")
	}
	if err := t.signer.SignHTTP(req.Context(), creds, req, s3EmptyPayloadHash, "s3", t.region, t.now()); err != nil {
		return nil, errors.Wrap(err, "sign S3 request")
	}
	resp, err := t.base.RoundTrip(req)
	return resp, errors.WithStack(err)
}
