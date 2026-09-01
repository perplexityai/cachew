package strategy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"golang.org/x/sync/singleflight"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/packagepolicy"
)

const codeArtifactUsername = "aws"

const (
	defaultCodeArtifactOriginHeaderTimeout   = 30 * time.Second
	defaultCodeArtifactOriginReadIdleTimeout = 30 * time.Second
	defaultCodeArtifactCredentialTimeout     = 15 * time.Second
)

// CodeArtifactConfig configures an authenticated, read-only CodeArtifact origin.
type CodeArtifactConfig struct {
	Target                string                `hcl:"target,label" help:"The CodeArtifact origin URL to proxy requests to."`
	ProxyBaseURL          string                `hcl:"proxy-base-url" help:"The public Cachew origin used when rewriting package metadata URLs."`
	Domain                string                `hcl:"domain" help:"The CodeArtifact domain name."`
	DomainOwner           string                `hcl:"domain-owner" help:"The AWS account ID that owns the CodeArtifact domain."`
	Region                string                `hcl:"region" help:"The AWS region containing the CodeArtifact domain."`
	RoleARN               string                `hcl:"role-arn" help:"The read-only IAM role to assume when minting CodeArtifact tokens."`
	OriginHeaderTimeout   time.Duration         `hcl:"origin-header-timeout,optional" default:"30s" help:"Maximum time to wait for CodeArtifact origin response headers. Zero uses the default."`
	OriginReadIdleTimeout time.Duration         `hcl:"origin-read-idle-timeout,optional" default:"30s" help:"Maximum time a read from the origin body may make no progress. Zero uses the default."`
	CredentialTimeout     time.Duration         `hcl:"credential-timeout,optional" default:"15s" help:"Maximum time to wait for CodeArtifact credential refresh, including a concurrent refresh. Zero uses the default."`
	PackagePolicy         *packagepolicy.Config `hcl:"package-policy,block,optional" help:"Optional package security policy enforced before cold npm and PyPI artifact reads."`
}

// CodeArtifact caches origin-declared immutable responses and passes all other
// authenticated reads through.
type CodeArtifact struct {
	target                *url.URL
	proxyBase             *url.URL
	prefix                string
	tokens                codeArtifactTokenSource
	cache                 cache.Cache
	client                *http.Client
	logger                *slog.Logger
	metric                codeArtifactMetricRecorder
	packagePolicy         packagepolicy.Evaluator
	fills                 singleflight.Group
	originReadIdleTimeout time.Duration
}

var _ Strategy = (*CodeArtifact)(nil)

type codeArtifactTokenSource interface {
	// Token returns a usable token. rejectedGeneration is zero for a normal
	// lookup. When non-zero, it identifies the token generation an origin
	// rejected so a concurrent refresh can be reused instead of repeated.
	Token(context.Context, uint64) (codeArtifactToken, error)
}

func RegisterCodeArtifact(r *Registry) {
	Register(r, "codeartifact", "Authenticated read-only proxy for AWS CodeArtifact.", NewCodeArtifact)
}

func NewCodeArtifact(ctx context.Context, config CodeArtifactConfig, configuredCache cache.Cache, mux Mux) (*CodeArtifact, error) {
	config = codeArtifactConfigWithDefaults(config)
	if _, _, err := validateCodeArtifactConfig(config, false); err != nil {
		return nil, err
	}
	tokens, err := newCodeArtifactTokenManager(ctx, config)
	if err != nil {
		return nil, err
	}
	strategy, err := newCodeArtifact(ctx, config, mux, tokens, configuredCache, false)
	if err != nil {
		return nil, err
	}
	if config.PackagePolicy != nil {
		strategy.packagePolicy, err = packagepolicy.New(*config.PackagePolicy)
		if err != nil {
			return nil, errors.Wrap(err, "create package policy")
		}
	}
	return strategy, nil
}

func newCodeArtifact(
	ctx context.Context,
	config CodeArtifactConfig,
	mux Mux,
	tokens codeArtifactTokenSource,
	configuredCache cache.Cache,
	allowHTTP bool,
) (*CodeArtifact, error) {
	target, proxyBase, err := validateCodeArtifactConfig(config, allowHTTP)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = config.OriginHeaderTimeout

	c := &CodeArtifact{
		target:    target,
		proxyBase: proxyBase,
		prefix:    "/" + target.Host,
		tokens:    tokens,
		cache:     configuredCache.Namespace(cache.Namespace("codeartifact")),
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:                logging.FromContext(ctx),
		metric:                newCodeArtifactMetrics(),
		originReadIdleTimeout: config.OriginReadIdleTimeout,
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		pattern := method + " " + c.prefix + "/"
		mux.Handle(pattern, c)
		c.logger.InfoContext(ctx, "Registered CodeArtifact route", "pattern", pattern, "target", target)
	}

	return c, nil
}

func codeArtifactConfigWithDefaults(config CodeArtifactConfig) CodeArtifactConfig {
	if config.OriginHeaderTimeout == 0 {
		config.OriginHeaderTimeout = defaultCodeArtifactOriginHeaderTimeout
	}
	if config.OriginReadIdleTimeout == 0 {
		config.OriginReadIdleTimeout = defaultCodeArtifactOriginReadIdleTimeout
	}
	if config.CredentialTimeout == 0 {
		config.CredentialTimeout = defaultCodeArtifactCredentialTimeout
	}
	return config
}

func validateCodeArtifactConfig(config CodeArtifactConfig, allowHTTP bool) (*url.URL, *url.URL, error) {
	timeouts := []struct {
		name  string
		value time.Duration
	}{
		{name: "origin-header-timeout", value: config.OriginHeaderTimeout},
		{name: "origin-read-idle-timeout", value: config.OriginReadIdleTimeout},
		{name: "credential-timeout", value: config.CredentialTimeout},
	}
	for _, timeout := range timeouts {
		if timeout.value < 0 {
			return nil, nil, errors.Errorf("codeartifact: %s must not be negative", timeout.name)
		}
	}

	missing := make([]string, 0, 6)
	configured := []struct {
		name  string
		value string
	}{
		{name: "target", value: config.Target},
		{name: "proxy-base-url", value: config.ProxyBaseURL},
		{name: "domain", value: config.Domain},
		{name: "domain-owner", value: config.DomainOwner},
		{name: "region", value: config.Region},
		{name: "role-arn", value: config.RoleARN},
	}
	for _, field := range configured {
		if field.value == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		return nil, nil, errors.Errorf("codeartifact: missing required configuration: %s", strings.Join(missing, ", "))
	}

	target, err := parseCodeArtifactOrigin("target", config.Target, allowHTTP)
	if err != nil {
		return nil, nil, err
	}
	proxyBase, err := parseCodeArtifactOrigin("proxy-base-url", config.ProxyBaseURL, allowHTTP)
	if err != nil {
		return nil, nil, err
	}
	return target, proxyBase, nil
}

func parseCodeArtifactOrigin(name, value string, allowHTTP bool) (*url.URL, error) {
	origin, err := url.Parse(value)
	if err != nil {
		return nil, errors.Errorf("codeartifact: invalid %s URL: %w", name, err)
	}
	validScheme := origin.Scheme == "https" || (allowHTTP && origin.Scheme == "http")
	if origin.Host == "" || !validScheme {
		return nil, errors.Errorf("codeartifact: %s must be an HTTPS origin", name)
	}
	if origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.Errorf("codeartifact: %s must not contain credentials, a path, query, or fragment", name)
	}
	origin.Path = ""
	return origin, nil
}

func (c *CodeArtifact) String() string { return "codeartifact:" + c.target.Host }

func (c *CodeArtifact) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mode := classifyCodeArtifactRequest(r)
	c.metric.recordRequest(r.Context(), mode)
	if mode != codeArtifactCacheLookup {
		c.serveOrigin(w, r, mode)
		return
	}
	if c.serveCached(w, r) {
		return
	}

	key := c.cacheKey(r)
	servedByThisRequest := false
	_, _, _ = c.fills.Do(key.String(), func() (any, error) { //nolint:errcheck // The callback reports failures through its response writer.
		servedByThisRequest = true
		c.serveOrigin(w, r, mode)
		return true, nil
	})
	if servedByThisRequest {
		return
	}
	if c.serveCached(w, r) {
		return
	}
	c.serveOrigin(w, r, mode)
}

func (c *CodeArtifact) serveOrigin(w http.ResponseWriter, r *http.Request, mode codeArtifactCacheMode) {
	if !c.allowPackage(w, r) {
		return
	}
	rewriteMetadata := shouldRewriteCodeArtifactMetadata(c.originURL(r).Path)
	token, authorized := c.authorizationToken(w, r)
	if !authorized {
		return
	}

	resp, err := c.do(r, token.value)
	if err != nil {
		c.writeError(w, r, err)
		return
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if err := resp.Body.Close(); err != nil {
			c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact response", "error", err)
		}
		refreshed, refreshErr := c.tokens.Token(r.Context(), token.generation)
		if refreshErr != nil {
			c.metric.recordAuth(r.Context(), codeArtifactAuthFailure)
			c.writeError(w, r, errors.Wrap(refreshErr, "refresh CodeArtifact authorization"))
			return
		}
		c.metric.recordAuth(r.Context(), refreshed.event)
		resp, err = c.do(r, refreshed.value)
		if err != nil {
			c.writeError(w, r, err)
			return
		}
	}
	responseHeaders := endToEndHeaders(resp.Header)
	responseHeaders.Del(codeArtifactOriginValidatorsHeader)
	responseHeaders.Del(cache.ExpirationKey)
	if location := responseHeaders.Get("Location"); location != "" {
		rewritten, ok := c.rewriteSameOriginLocation(resp.Request.URL, location)
		if ok {
			responseHeaders.Set("Location", rewritten)
			c.metric.recordRedirect(r.Context(), codeArtifactRedirectSameOrigin)
		} else {
			if err := resp.Body.Close(); err != nil {
				c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact response", "error", err)
			}
			resp, err = c.followCrossOriginRedirect(r, resp, location, rewriteMetadata)
			if err != nil {
				c.metric.recordRedirect(r.Context(), codeArtifactRedirectFailure)
				c.writeError(w, r, err)
				return
			}
			c.metric.recordRedirect(r.Context(), codeArtifactRedirectCrossOrigin)
			if resp.Header.Get("Location") != "" {
				if err := resp.Body.Close(); err != nil {
					c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact response", "error", err)
				}
				c.metric.recordRedirect(r.Context(), codeArtifactRedirectChainedRejected)
				c.writeError(w, r, errors.New("CodeArtifact redirect target returned another redirect"))
				return
			}
			responseHeaders = endToEndHeaders(resp.Header)
		}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact response", "error", err)
		}
	}()
	responseHeaders, err = c.rewriteOriginMetadata(resp, responseHeaders, r, rewriteMetadata)
	if err != nil {
		c.writeError(w, r, err)
		return
	}
	sanitizeCodeArtifactETag(responseHeaders)
	copyHeaders(w.Header(), responseHeaders)
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	if mode == codeArtifactCacheLookup && resp.StatusCode == http.StatusOK {
		c.streamAndCache(w, r, resp, responseHeaders)
		return
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		c.logger.ErrorContext(r.Context(), "Failed to stream CodeArtifact response", "error", err)
	}
}

func (c *CodeArtifact) authorizationToken(w http.ResponseWriter, r *http.Request) (codeArtifactToken, bool) {
	token, err := c.tokens.Token(r.Context(), 0)
	if err != nil {
		c.metric.recordAuth(r.Context(), codeArtifactAuthFailure)
		c.writeError(w, r, errors.Wrap(err, "obtain CodeArtifact authorization"))
		return codeArtifactToken{}, false
	}
	c.metric.recordAuth(r.Context(), token.event)
	return token, true
}

func (c *CodeArtifact) allowPackage(w http.ResponseWriter, r *http.Request) bool {
	if c.packagePolicy == nil || r.Method != http.MethodGet {
		return true
	}
	purl, ok := packagepolicy.PackageURLForCodeArtifact(c.originURL(r).Path)
	if !ok {
		c.packagePolicy.ObserveNotApplicable(r.Context())
		return true
	}
	decision, err := c.packagePolicy.Evaluate(r.Context(), purl)
	if err != nil {
		c.logger.ErrorContext(r.Context(), "Package policy evaluation failed", "error", err)
	}
	return packagepolicy.AllowRequest(w, decision, err)
}

func (c *CodeArtifact) rewriteOriginMetadata(
	resp *http.Response,
	headers http.Header,
	r *http.Request,
	rewrite bool,
) (http.Header, error) {
	if !rewrite || resp.StatusCode != http.StatusOK {
		return headers, nil
	}
	originPath := c.originURL(r).Path
	if !isCodeArtifactJSONResponse(originPath, headers) {
		if isCodeArtifactSwiftArchiveResponse(originPath, headers) {
			return headers, nil
		}
		return nil, errors.New("CodeArtifact package metadata is not JSON")
	}
	return c.rewriteMetadataResponse(resp, headers, r.Method, originPath)
}

func (c *CodeArtifact) do(r *http.Request, token string) (*http.Response, error) {
	target := c.originURL(r)
	started := time.Now()
	originCtx, cancel := context.WithCancelCause(r.Context())

	upstream, err := http.NewRequestWithContext(originCtx, r.Method, target.String(), nil)
	if err != nil {
		cancel(nil)
		return nil, errors.New("build CodeArtifact request")
	}
	copyHeaders(upstream.Header, codeArtifactRequestHeaders(r.Header))
	if shouldRewriteCodeArtifactMetadata(target.Path) {
		normalizeCodeArtifactMetadataRequestHeaders(upstream.Header, target.Path)
	}
	setCodeArtifactAuthorization(upstream, token)

	resp, err := c.client.Do(upstream)
	if err != nil {
		cancel(nil)
		if c.metric != nil {
			c.metric.recordOrigin(r.Context(), codeArtifactOriginObservation{
				status: "transport_error", format: codeArtifactMetricFormat(target.Path), duration: time.Since(started),
			})
		}
		// http.Client errors include the full request URL. Do not retain that
		// client-controlled value because callers log this error.
		return nil, errors.New("request CodeArtifact origin")
	}
	resp.Body = newCodeArtifactOriginBody(originCtx, resp.Body, cancel, c.originReadIdleTimeout)
	c.observeOriginResponse(r.Context(), resp, target.Path, started)
	return resp, nil
}

func setCodeArtifactAuthorization(r *http.Request, token string) {
	if strings.HasPrefix(r.URL.Path, "/cargo/") {
		r.Header.Set("Authorization", token)
		return
	}
	r.SetBasicAuth(codeArtifactUsername, token)
}

func (c *CodeArtifact) originURL(r *http.Request) url.URL {
	target := *c.target
	target.Path = strings.TrimPrefix(r.URL.Path, c.prefix)
	if escapedPath := r.URL.EscapedPath(); escapedPath != r.URL.Path {
		target.RawPath = strings.TrimPrefix(escapedPath, c.prefix)
	}
	target.RawQuery = r.URL.RawQuery
	return target
}

func (c *CodeArtifact) rewriteSameOriginLocation(requestURL *url.URL, location string) (string, bool) {
	parsed, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	resolved := requestURL.ResolveReference(parsed)
	if !strings.EqualFold(resolved.Scheme, c.target.Scheme) || !strings.EqualFold(resolved.Host, c.target.Host) {
		return "", false
	}

	rewritten := &url.URL{
		Path:     c.prefix + resolved.Path,
		RawQuery: resolved.RawQuery,
		Fragment: resolved.Fragment,
	}
	if resolved.RawPath != "" {
		rewritten.RawPath = c.prefix + resolved.RawPath
	}
	return rewritten.String(), true
}

func (c *CodeArtifact) followCrossOriginRedirect(
	r *http.Request,
	originResponse *http.Response,
	location string,
	rewriteMetadata bool,
) (*http.Response, error) {
	started := time.Now()
	switch originResponse.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil, errors.New("CodeArtifact origin returned an invalid cross-origin redirect")
	}

	parsed, err := url.Parse(location)
	if err != nil {
		return nil, errors.New("parse CodeArtifact redirect")
	}
	resolved := originResponse.Request.URL.ResolveReference(parsed)
	if !strings.EqualFold(resolved.Scheme, "https") {
		return nil, errors.New("CodeArtifact origin returned an insecure cross-origin redirect")
	}

	redirectCtx, cancel := context.WithCancelCause(r.Context())
	redirected, err := http.NewRequestWithContext(redirectCtx, r.Method, resolved.String(), nil)
	if err != nil {
		cancel(nil)
		return nil, errors.New("build CodeArtifact redirect request")
	}
	copyHeaders(redirected.Header, codeArtifactRequestHeaders(r.Header))
	if rewriteMetadata {
		normalizeCodeArtifactMetadataRequestHeaders(redirected.Header, c.originURL(r).Path)
	}

	resp, err := c.client.Do(redirected)
	if err != nil {
		cancel(nil)
		if c.metric != nil {
			c.metric.recordOrigin(r.Context(), codeArtifactOriginObservation{
				status: "transport_error", format: codeArtifactMetricFormat(resolved.Path), duration: time.Since(started),
			})
		}
		// A signed redirect URL is credential-bearing. Do not retain the
		// http.Client error because it includes the full request URL.
		return nil, errors.New("request CodeArtifact redirect")
	}
	resp.Body = newCodeArtifactOriginBody(redirectCtx, resp.Body, cancel, c.originReadIdleTimeout)
	c.observeOriginResponse(r.Context(), resp, resolved.Path, started)
	return resp, nil
}

func (c *CodeArtifact) observeOriginResponse(ctx context.Context, resp *http.Response, path string, started time.Time) {
	if c.metric == nil {
		return
	}
	resp.Body = &observedCodeArtifactBody{
		ReadCloser: resp.Body,
		ctx:        ctx,
		metric:     c.metric,
		status:     resp.StatusCode,
		format:     codeArtifactMetricFormat(path),
		started:    started,
	}
}

func codeArtifactMetricFormat(path string) string {
	format := codeArtifactPackageFormat(path)
	switch format {
	case codeArtifactCargoFormat, "generic", "maven", "npm", "nuget", "pypi", "ruby", codeArtifactSwiftFormat:
		return format
	default:
		return "other"
	}
}

func (c *CodeArtifact) writeError(w http.ResponseWriter, r *http.Request, err error) {
	c.logger.ErrorContext(r.Context(), "CodeArtifact request failed", "error", err)
	http.Error(w, "CodeArtifact origin unavailable", http.StatusBadGateway)
}

func endToEndHeaders(headers http.Header) http.Header {
	skip := append([]string{"Proxy-Connection", "Trailer"}, httputil.HopByHopHeaders...)
	for _, connection := range headers.Values("Connection") {
		for value := range strings.SplitSeq(connection, ",") {
			skip = append(skip, strings.TrimSpace(value))
		}
	}
	return httputil.FilterHeaders(headers, skip...)
}

func codeArtifactRequestHeaders(headers http.Header) http.Header {
	allowed := make(http.Header)
	for _, name := range []string{
		"Accept",
		"Accept-Encoding",
		"If-Match",
		"If-Modified-Since",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
		"Range",
	} {
		for _, value := range headers.Values(name) {
			allowed.Add(name, value)
		}
	}
	return allowed
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}
