package strategy

import (
	"context"
	"io"
	"maps"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
)

type codeArtifactCacheMode string

const (
	codeArtifactCacheLookup            codeArtifactCacheMode = "lookup"
	codeArtifactCachePassthrough       codeArtifactCacheMode = "passthrough"
	codeArtifactOriginValidatorsHeader                       = "X-Cachew-Codeartifact-Origin-Validators"
)

func classifyCodeArtifactRequest(r *http.Request) codeArtifactCacheMode {
	if r.Method != http.MethodGet || r.Header.Get("Range") != "" || r.URL.RawQuery != "" {
		return codeArtifactCachePassthrough
	}
	if strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") {
		return codeArtifactCachePassthrough
	}
	return codeArtifactCacheLookup
}

func (c *CodeArtifact) cacheKey(r *http.Request) cache.Key {
	origin := c.originURL(r)
	var key strings.Builder
	key.WriteString(origin.String())
	for _, name := range []string{"Accept", "Accept-Encoding"} {
		if values := r.Header.Values(name); len(values) > 0 {
			key.WriteByte('\n')
			key.WriteString(name)
			key.WriteByte('=')
			key.WriteString(strings.Join(values, ","))
		}
	}
	return cache.NewKey(key.String())
}

func (c *CodeArtifact) serveCached(w http.ResponseWriter, r *http.Request) bool {
	body, headers, err := c.cache.Open(r.Context(), c.cacheKey(r))
	if err == nil {
		headers = codeArtifactOriginHeaders(headers, time.Now())
		if status := cachedPreconditionStatus(r, headers); status != 0 {
			c.metric.recordCache(r.Context(), codeArtifactCacheHit)
			if closeErr := body.Close(); closeErr != nil {
				c.logger.ErrorContext(r.Context(), "Failed to close cached CodeArtifact response", "error", closeErr)
			}
			if status == http.StatusNotModified {
				copyHeaders(w.Header(), headers)
			}
			w.WriteHeader(status)
			return true
		}
	}
	if handled, _, serveErr := httputil.ServeCacheHit(w, headers, body, err); handled {
		c.metric.recordCache(r.Context(), codeArtifactCacheHit)
		if serveErr != nil {
			c.logger.ErrorContext(r.Context(), "Failed to serve cached CodeArtifact response", "error", serveErr)
		}
		return true
	}
	if errors.Is(err, os.ErrNotExist) {
		c.metric.recordCache(r.Context(), codeArtifactCacheMiss)
		return false
	}
	c.metric.recordCache(r.Context(), codeArtifactCacheReadFailure)
	c.logger.ErrorContext(r.Context(), "Failed to read CodeArtifact cache", "error", err)
	return false
}

func (c *CodeArtifact) streamAndCache(
	w http.ResponseWriter,
	r *http.Request,
	resp *http.Response,
	responseHeaders http.Header,
) {
	cacheHeaders, ttl, createOptions, cacheable := codeArtifactCacheEntry(responseHeaders, time.Now())
	if !cacheable {
		c.metric.recordCache(r.Context(), codeArtifactCacheNotCacheable)
		c.streamOriginBody(r.Context(), w, resp.Body)
		return
	}

	writer, err := c.cache.Create(r.Context(), c.cacheKey(r), cacheHeaders, ttl, createOptions...)
	if err != nil {
		c.metric.recordCache(r.Context(), codeArtifactCacheWriteFailure)
		c.logger.ErrorContext(r.Context(), "Failed to create CodeArtifact cache entry", "error", err)
		c.streamOriginBody(r.Context(), w, resp.Body)
		return
	}

	cacheCopy := &bestEffortCacheWriter{writer: writer}
	_, copyErr := io.Copy(w, io.TeeReader(resp.Body, cacheCopy))
	if copyErr != nil || cacheCopy.err != nil {
		abortErr := writer.Abort(errors.Join(copyErr, cacheCopy.err))
		c.metric.recordCache(r.Context(), codeArtifactCacheWriteFailure)
		if err := errors.Join(copyErr, cacheCopy.err, abortErr); err != nil {
			c.logger.ErrorContext(r.Context(), "Failed to cache complete CodeArtifact response", "error", err)
		}
		return
	}
	if err := writer.Close(); err != nil {
		c.metric.recordCache(r.Context(), codeArtifactCacheWriteFailure)
		c.logger.ErrorContext(r.Context(), "Failed to commit CodeArtifact cache entry", "error", err)
		return
	}
	c.metric.recordCache(r.Context(), codeArtifactCacheStored)
}

func codeArtifactCacheEntry(headers http.Header, now time.Time) (http.Header, time.Duration, []cache.Option, bool) {
	directives, ok := parseCodeArtifactCacheControl(headers.Values("Cache-Control"))
	if !ok || !codeArtifactSharedCachePolicyAllowsStorage(directives) || !supportedCodeArtifactVary(headers.Values("Vary")) {
		return nil, 0, nil, false
	}
	if headers.Get("Set-Cookie") != "" {
		return nil, 0, nil, false
	}
	ttl, ok := codeArtifactFreshnessLifetime(headers, directives, now)
	if !ok {
		return nil, 0, nil, false
	}
	cacheHeaders := maps.Clone(headers)
	cacheHeaders.Set(cache.ExpirationKey, now.Add(ttl).UTC().Format(time.RFC3339Nano))
	validators := make([]string, 0, 2)
	var createOptions []cache.Option
	etag := cacheHeaders.Get(cache.ETagKey)
	if etag != "" {
		rawETag, err := cache.RawETagFromHeader(etag)
		if err != nil {
			return nil, 0, nil, false
		}
		validators = append(validators, "etag")
		createOptions = []cache.Option{cache.WithETag(rawETag)}
	}
	if cacheHeaders.Get("Last-Modified") != "" {
		validators = append(validators, "last-modified")
	}
	cacheHeaders.Set(codeArtifactOriginValidatorsHeader, strings.Join(validators, ","))
	return cacheHeaders, ttl, createOptions, true
}

func parseCodeArtifactCacheControl(values []string) (map[string]string, bool) {
	directives := make(map[string]string)
	for _, value := range values {
		for directive := range strings.SplitSeq(value, ",") {
			name, argument, hasArgument := strings.Cut(strings.TrimSpace(directive), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if _, duplicate := directives[name]; duplicate {
				return nil, false
			}
			if hasArgument {
				argument = strings.TrimSpace(argument)
				if strings.HasPrefix(argument, `"`) {
					unquoted, err := strconv.Unquote(argument)
					if err != nil {
						return nil, false
					}
					argument = unquoted
				}
			}
			directives[name] = argument
		}
	}
	return directives, true
}

func codeArtifactSharedCachePolicyAllowsStorage(directives map[string]string) bool {
	for _, required := range []string{"public", "immutable"} {
		if argument, ok := directives[required]; !ok || argument != "" {
			return false
		}
	}
	for _, forbidden := range []string{"no-cache", "no-store", "private"} {
		if _, ok := directives[forbidden]; ok {
			return false
		}
	}
	return true
}

func supportedCodeArtifactVary(values []string) bool {
	for _, value := range values {
		for field := range strings.SplitSeq(value, ",") {
			switch strings.ToLower(strings.TrimSpace(field)) {
			case "", "accept", "accept-encoding":
			case "*":
				return false
			default:
				return false
			}
		}
	}
	return true
}

func codeArtifactFreshnessLifetime(headers http.Header, directives map[string]string, now time.Time) (time.Duration, bool) {
	value, ok := directives["s-maxage"]
	if !ok {
		value, ok = directives["max-age"]
	}
	if !ok {
		return 0, false
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 || seconds > int64(time.Duration(1<<63-1)/time.Second) {
		return 0, false
	}

	age := time.Duration(0)
	if ageValue := headers.Get("Age"); ageValue != "" {
		ageSeconds, err := strconv.ParseInt(ageValue, 10, 64)
		if err != nil || ageSeconds < 0 || ageSeconds > int64(time.Duration(1<<63-1)/time.Second) {
			return 0, false
		}
		age = time.Duration(ageSeconds) * time.Second
	}
	if date, err := http.ParseTime(headers.Get("Date")); err == nil && now.After(date) {
		age = max(age, now.Sub(date))
	}
	ttl := time.Duration(seconds)*time.Second - age
	return ttl, ttl > 0
}

func codeArtifactOriginHeaders(headers http.Header, now time.Time) http.Header {
	originHeaders := maps.Clone(headers)
	updateCodeArtifactAge(originHeaders, now)
	originHeaders.Del(cache.ExpirationKey)
	validators := originHeaders.Get(codeArtifactOriginValidatorsHeader)
	originHeaders.Del(codeArtifactOriginValidatorsHeader)
	if !commaSeparatedValueContains(validators, "etag") {
		originHeaders.Del(cache.ETagKey)
	}
	if !commaSeparatedValueContains(validators, "last-modified") {
		originHeaders.Del("Last-Modified")
	}
	return originHeaders
}

func updateCodeArtifactAge(headers http.Header, now time.Time) {
	expiresAt, err := time.Parse(time.RFC3339Nano, headers.Get(cache.ExpirationKey))
	if err != nil {
		return
	}
	directives, ok := parseCodeArtifactCacheControl(headers.Values("Cache-Control"))
	if !ok {
		return
	}
	value, ok := directives["s-maxage"]
	if !ok {
		value, ok = directives["max-age"]
	}
	if !ok {
		return
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 || seconds > int64(time.Duration(1<<63-1)/time.Second) {
		return
	}
	age := time.Duration(seconds)*time.Second - expiresAt.Sub(now)
	age = max(age, 0)
	headers.Set("Age", strconv.FormatInt(int64(age/time.Second), 10))
}

func cachedPreconditionStatus(r *http.Request, headers http.Header) int {
	etag := headers.Get(cache.ETagKey)
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		if !strongETagListMatches(ifMatch, etag) {
			return http.StatusPreconditionFailed
		}
	} else {
		if status := unmodifiedSinceStatus(r, headers); status != 0 {
			return status
		}
	}

	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if weakETagListMatches(ifNoneMatch, etag) {
			return http.StatusNotModified
		}
		return 0
	}
	return modifiedSinceStatus(r, headers)
}

func unmodifiedSinceStatus(r *http.Request, headers http.Header) int {
	lastModified, err := http.ParseTime(headers.Get("Last-Modified"))
	if err != nil {
		return 0
	}
	unmodifiedSince, err := http.ParseTime(r.Header.Get("If-Unmodified-Since"))
	if err == nil && lastModified.After(unmodifiedSince) {
		return http.StatusPreconditionFailed
	}
	return 0
}

func modifiedSinceStatus(r *http.Request, headers http.Header) int {
	lastModified, err := http.ParseTime(headers.Get("Last-Modified"))
	if err != nil {
		return 0
	}
	modifiedSince, err := http.ParseTime(r.Header.Get("If-Modified-Since"))
	if err == nil && !lastModified.After(modifiedSince) {
		return http.StatusNotModified
	}
	return 0
}

func strongETagListMatches(headerValue, etag string) bool {
	for candidate := range strings.SplitSeq(headerValue, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || (etag != "" && !strings.HasPrefix(candidate, "W/") && candidate == etag) {
			return true
		}
	}
	return false
}

func weakETagListMatches(headerValue, etag string) bool {
	for candidate := range strings.SplitSeq(headerValue, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || (etag != "" && strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(etag, "W/")) {
			return true
		}
	}
	return false
}

func commaSeparatedValueContains(headerValue, want string) bool {
	for value := range strings.SplitSeq(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func (c *CodeArtifact) streamOriginBody(ctx context.Context, w http.ResponseWriter, body io.Reader) {
	if _, err := io.Copy(w, body); err != nil {
		c.logger.ErrorContext(ctx, "Failed to stream CodeArtifact response", "error", err)
	}
}

type bestEffortCacheWriter struct {
	writer cache.Writer
	err    error
}

func (w *bestEffortCacheWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return len(p), nil //nolint:nilerr // Cache failures must not interrupt the response stream.
	}
	written, err := w.writer.Write(p)
	if err != nil {
		w.err = err
		return len(p), nil //nolint:nilerr // Cache failures must not interrupt the response stream.
	}
	if written != len(p) {
		w.err = io.ErrShortWrite
	}
	return len(p), nil
}

var _ io.Writer = (*bestEffortCacheWriter)(nil)
