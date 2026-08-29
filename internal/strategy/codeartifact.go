package strategy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
)

const codeArtifactUsername = "aws"

const (
	codeArtifactAuthorizationBasic  = "basic"
	codeArtifactAuthorizationBearer = "bearer"
)

// CodeArtifactConfig configures an authenticated, read-only CodeArtifact origin.
type CodeArtifactConfig struct {
	Target              string `hcl:"target,label" help:"The logical CodeArtifact origin represented by this route."`
	Domain              string `hcl:"domain" help:"The CodeArtifact domain name."`
	DomainOwner         string `hcl:"domain-owner" help:"The AWS account ID that owns the CodeArtifact domain."`
	Region              string `hcl:"region" help:"The AWS region containing the CodeArtifact domain."`
	RoleARN             string `hcl:"role-arn" help:"The read-only IAM role to assume when minting CodeArtifact tokens."`
	Upstream            string `hcl:"upstream,optional" help:"An optional HTTPS validation proxy that receives origin requests."`
	RoutePrefix         string `hcl:"route-prefix,optional" help:"An optional public path prefix instead of the target hostname."`
	AuthorizationScheme string `hcl:"authorization-scheme,optional" help:"The upstream CodeArtifact token scheme: basic or bearer."`
	CacheRequiredHeader string `hcl:"cache-required-header,optional" help:"A response header required before an immutable response may be cached."`
	CacheRequiredValue  string `hcl:"cache-required-value,optional" help:"The exact required cache response header value."`
	CacheRejectedHeader string `hcl:"cache-rejected-header,optional" help:"A response header that prevents caching when it has the rejected value."`
	CacheRejectedValue  string `hcl:"cache-rejected-value,optional" help:"The exact response header value that prevents caching."`
}

// CodeArtifact caches reviewed immutable assets and passes all other
// authenticated reads through so classifier gaps cannot break package access.
type CodeArtifact struct {
	target              *url.URL
	upstream            *url.URL
	prefix              string
	routePrefix         string
	authorizationScheme string
	cacheRequiredHeader string
	cacheRequiredValue  string
	cacheRejectedHeader string
	cacheRejectedValue  string
	tokens              codeArtifactTokenSource
	cache               cache.Cache
	client              *http.Client
	logger              *slog.Logger
	metric              codeArtifactMetricRecorder
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
	if _, err := validateCodeArtifactConfig(config, false); err != nil {
		return nil, err
	}
	tokens, err := newCodeArtifactTokenManager(ctx, config)
	if err != nil {
		return nil, err
	}
	return newCodeArtifact(ctx, config, mux, tokens, configuredCache, false)
}

func newCodeArtifact(
	ctx context.Context,
	config CodeArtifactConfig,
	mux Mux,
	tokens codeArtifactTokenSource,
	configuredCache cache.Cache,
	allowHTTP bool,
) (*CodeArtifact, error) {
	target, err := validateCodeArtifactConfig(config, allowHTTP)
	if err != nil {
		return nil, err
	}
	upstream, err := validateCodeArtifactUpstream(config.Upstream, allowHTTP)
	if err != nil {
		return nil, err
	}
	prefix, err := codeArtifactRoutePrefix(config.RoutePrefix, target)
	if err != nil {
		return nil, err
	}
	authorizationScheme, err := codeArtifactAuthorization(config.AuthorizationScheme)
	if err != nil {
		return nil, err
	}
	if err := validateCodeArtifactCacheHeaders(config); err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true

	c := &CodeArtifact{
		target:              target,
		upstream:            upstream,
		prefix:              prefix,
		routePrefix:         config.RoutePrefix,
		authorizationScheme: authorizationScheme,
		cacheRequiredHeader: config.CacheRequiredHeader,
		cacheRequiredValue:  config.CacheRequiredValue,
		cacheRejectedHeader: config.CacheRejectedHeader,
		cacheRejectedValue:  config.CacheRejectedValue,
		tokens:              tokens,
		cache:               configuredCache.Namespace(cache.Namespace("codeartifact")),
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logging.FromContext(ctx),
		metric: newCodeArtifactMetrics(),
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		pattern := method + " " + c.prefix + "/"
		mux.Handle(pattern, c)
		c.logger.InfoContext(ctx, "Registered CodeArtifact route", "pattern", pattern, "target", target)
	}

	return c, nil
}

func validateCodeArtifactUpstream(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	upstream, err := url.Parse(raw)
	if err != nil {
		return nil, errors.Errorf("codeartifact: invalid upstream URL: %w", err)
	}
	loopbackHTTP := upstream.Scheme == "http" && net.ParseIP(upstream.Hostname()).IsLoopback()
	validScheme := upstream.Scheme == "https" || loopbackHTTP || (allowHTTP && upstream.Scheme == "http")
	if upstream.Host == "" || !validScheme {
		return nil, errors.New("codeartifact: upstream must be an HTTPS or loopback HTTP origin")
	}
	if upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" || (upstream.Path != "" && upstream.Path != "/") {
		return nil, errors.New("codeartifact: upstream must not contain credentials, a path, query, or fragment")
	}
	upstream.Path = ""
	return upstream, nil
}

func codeArtifactRoutePrefix(configured string, target *url.URL) (string, error) {
	if configured == "" {
		return "/" + target.Host, nil
	}
	if configured == "/" || !strings.HasPrefix(configured, "/") || strings.HasSuffix(configured, "/") {
		return "", errors.New("codeartifact: route-prefix must start with one slash and must not end with a slash")
	}
	return configured, nil
}

func codeArtifactAuthorization(configured string) (string, error) {
	if configured == "" {
		return codeArtifactAuthorizationBasic, nil
	}
	if configured != codeArtifactAuthorizationBasic && configured != codeArtifactAuthorizationBearer {
		return "", errors.Errorf("codeartifact: authorization-scheme must be %q or %q", codeArtifactAuthorizationBasic, codeArtifactAuthorizationBearer)
	}
	return configured, nil
}

func validateCodeArtifactCacheHeaders(config CodeArtifactConfig) error {
	if (config.CacheRequiredHeader == "") != (config.CacheRequiredValue == "") {
		return errors.New("codeartifact: cache-required-header and cache-required-value must be configured together")
	}
	if (config.CacheRejectedHeader == "") != (config.CacheRejectedValue == "") {
		return errors.New("codeartifact: cache-rejected-header and cache-rejected-value must be configured together")
	}
	return nil
}

func validateCodeArtifactConfig(config CodeArtifactConfig, allowHTTP bool) (*url.URL, error) {
	missing := make([]string, 0, 5)
	configured := []struct {
		name  string
		value string
	}{
		{name: "target", value: config.Target},
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
		return nil, errors.Errorf("codeartifact: missing required configuration: %s", strings.Join(missing, ", "))
	}

	target, err := url.Parse(config.Target)
	if err != nil {
		return nil, errors.Errorf("codeartifact: invalid target URL: %w", err)
	}
	validScheme := target.Scheme == "https" || (allowHTTP && target.Scheme == "http")
	if target.Host == "" || !validScheme {
		return nil, errors.Errorf("codeartifact: target must be an HTTPS origin")
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, errors.Errorf("codeartifact: target must not contain credentials, a path, query, or fragment")
	}
	if target.Path != "" && target.Path != "/" {
		return nil, errors.Errorf("codeartifact: target must not contain credentials, a path, query, or fragment")
	}
	target.Path = ""
	return target, nil
}

func (c *CodeArtifact) String() string { return "codeartifact:" + c.target.Host }

func (c *CodeArtifact) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mode := classifyCodeArtifactRequest(r, c.prefix, c.routePrefix)
	c.metric.recordRequest(r.Context(), mode)
	if mode == codeArtifactCacheImmutable && c.serveCached(w, r) {
		return
	}
	c.serveOrigin(w, r, mode)
}

func (c *CodeArtifact) serveOrigin(w http.ResponseWriter, r *http.Request, mode codeArtifactCacheMode) {
	token, err := c.tokens.Token(r.Context(), 0)
	if err != nil {
		c.metric.recordAuth(r.Context(), codeArtifactAuthFailure)
		c.writeError(w, r, errors.Wrap(err, "obtain CodeArtifact authorization"))
		return
	}
	c.metric.recordAuth(r.Context(), token.event)

	resp, err := c.do(r, token.value)
	if err != nil {
		c.writeError(w, r, err)
		return
	}

	if c.shouldRefreshToken(resp) {
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
	if location := responseHeaders.Get("Location"); location != "" {
		rewritten, ok := c.rewriteSameOriginLocation(resp.Request.URL, location)
		if ok {
			responseHeaders.Set("Location", rewritten)
		} else {
			if err := resp.Body.Close(); err != nil {
				c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact response", "error", err)
			}
			resp, err = c.followCrossOriginRedirect(r, resp, location)
			if err != nil {
				c.writeError(w, r, err)
				return
			}
			if resp.Header.Get("Location") != "" {
				if err := resp.Body.Close(); err != nil {
					c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact response", "error", err)
				}
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
	copyHeaders(w.Header(), responseHeaders)
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	if mode == codeArtifactCacheImmutable && resp.StatusCode == http.StatusOK && c.cacheResponseAllowed(responseHeaders) {
		c.streamAndCache(w, r, resp, responseHeaders)
		return
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		c.logger.ErrorContext(r.Context(), "Failed to stream CodeArtifact response", "error", err)
	}
}

func (c *CodeArtifact) shouldRefreshToken(resp *http.Response) bool {
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return false
	}
	if c.cacheRequiredHeader == "" {
		return true
	}
	decision := resp.Header.Get(c.cacheRequiredHeader)
	return decision == "" || decision == c.cacheRequiredValue
}

func (c *CodeArtifact) do(r *http.Request, token string) (*http.Response, error) {
	target := c.upstreamURL(r)

	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		return nil, errors.New("build CodeArtifact request")
	}
	copyHeaders(upstream.Header, codeArtifactRequestHeaders(r.Header))
	if c.authorizationScheme == codeArtifactAuthorizationBearer {
		upstream.Header.Set("Authorization", "Bearer "+token)
	} else {
		upstream.SetBasicAuth(codeArtifactUsername, token)
	}

	resp, err := c.client.Do(upstream)
	if err != nil {
		// http.Client errors include the full request URL. Do not retain that
		// client-controlled value because callers log this error.
		return nil, errors.New("request CodeArtifact origin")
	}
	return resp, nil
}

func (c *CodeArtifact) upstreamURL(r *http.Request) url.URL {
	if c.upstream == nil {
		return c.originURL(r)
	}
	target := *c.upstream
	target.Path = r.URL.Path
	if escapedPath := r.URL.EscapedPath(); escapedPath != r.URL.Path {
		target.RawPath = escapedPath
	}
	target.RawQuery = r.URL.RawQuery
	return target
}

func (c *CodeArtifact) originURL(r *http.Request) url.URL {
	target := *c.target
	target.Path = strings.TrimPrefix(r.URL.Path, c.prefix)
	if c.routePrefix != "" {
		target.Path = r.URL.Path
	}
	if escapedPath := r.URL.EscapedPath(); escapedPath != r.URL.Path {
		target.RawPath = strings.TrimPrefix(escapedPath, c.prefix)
		if c.routePrefix != "" {
			target.RawPath = escapedPath
		}
	}
	target.RawQuery = r.URL.RawQuery
	return target
}

func (c *CodeArtifact) cacheResponseAllowed(headers http.Header) bool {
	if c.cacheRequiredHeader != "" && headers.Get(c.cacheRequiredHeader) != c.cacheRequiredValue {
		return false
	}
	return c.cacheRejectedHeader == "" || headers.Get(c.cacheRejectedHeader) != c.cacheRejectedValue
}

func (c *CodeArtifact) rewriteSameOriginLocation(requestURL *url.URL, location string) (string, bool) {
	parsed, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	resolved := requestURL.ResolveReference(parsed)
	if !strings.EqualFold(resolved.Scheme, requestURL.Scheme) || !strings.EqualFold(resolved.Host, requestURL.Host) {
		return "", false
	}

	pathPrefix := c.prefix
	if c.routePrefix != "" {
		pathPrefix = ""
	}
	rewritten := &url.URL{
		Path:     pathPrefix + resolved.Path,
		RawQuery: resolved.RawQuery,
		Fragment: resolved.Fragment,
	}
	if resolved.RawPath != "" {
		rewritten.RawPath = pathPrefix + resolved.RawPath
	}
	return rewritten.String(), true
}

func (c *CodeArtifact) followCrossOriginRedirect(
	r *http.Request,
	originResponse *http.Response,
	location string,
) (*http.Response, error) {
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

	redirected, err := http.NewRequestWithContext(r.Context(), r.Method, resolved.String(), nil)
	if err != nil {
		return nil, errors.New("build CodeArtifact redirect request")
	}
	copyHeaders(redirected.Header, codeArtifactRequestHeaders(r.Header))

	resp, err := c.client.Do(redirected)
	if err != nil {
		// A signed redirect URL is credential-bearing. Do not retain the
		// http.Client error because it includes the full request URL.
		return nil, errors.New("request CodeArtifact redirect")
	}
	return resp, nil
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
