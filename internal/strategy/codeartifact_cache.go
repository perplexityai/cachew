package strategy

import (
	"context"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
)

type codeArtifactCacheMode string

const (
	codeArtifactCacheImmutable         codeArtifactCacheMode = "immutable"
	codeArtifactCachePassthrough       codeArtifactCacheMode = "passthrough"
	codeArtifactOriginValidatorsHeader                       = "X-Cachew-Codeartifact-Origin-Validators"
)

func classifyCodeArtifactRequest(r *http.Request, prefix string) codeArtifactCacheMode {
	if r.Method != http.MethodGet || r.Header.Get("Range") != "" {
		return codeArtifactCachePassthrough
	}
	escapedPath := strings.ToLower(r.URL.EscapedPath())
	if strings.Contains(escapedPath, "%2f") {
		return codeArtifactCachePassthrough
	}

	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if isImmutableMavenAsset(parts) || isImmutableGenericAsset(parts) {
		return codeArtifactCacheImmutable
	}
	return codeArtifactCachePassthrough
}

func isImmutableMavenAsset(parts []string) bool {
	if len(parts) < 6 || parts[0] != "maven" {
		return false
	}
	artifact, version, filename := parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1]
	if artifact == "" || version == "" || filename == "" || strings.EqualFold(filename, "maven-metadata.xml") {
		return false
	}
	if strings.HasSuffix(strings.ToUpper(version), "-SNAPSHOT") {
		return false
	}
	return strings.HasPrefix(filename, artifact+"-"+version)
}

func isImmutableGenericAsset(parts []string) bool {
	if len(parts) < 6 || parts[0] != "generic" {
		return false
	}
	if slices.Contains(parts[1:], "") {
		return false
	}
	return isReviewedImmutableGenericVersion(parts[4])
}

func isReviewedImmutableGenericVersion(version string) bool {
	// Generic version strings are unconstrained and may be mutable aliases.
	// The initial cache contract reviews only canonical stable semantic versions.
	version = strings.TrimPrefix(version, "v")
	components := strings.Split(version, ".")
	if len(components) != 3 {
		return false
	}
	for _, component := range components {
		if component == "" || (len(component) > 1 && component[0] == '0') {
			return false
		}
		for _, char := range component {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func (c *CodeArtifact) cacheKey(r *http.Request) cache.Key {
	origin := c.originURL(r)
	key := origin.String()
	if encoding := r.Header.Get("Accept-Encoding"); encoding != "" {
		key += "\nAccept-Encoding=" + encoding
	}
	return cache.NewKey(key)
}

func (c *CodeArtifact) serveCached(w http.ResponseWriter, r *http.Request) bool {
	body, headers, err := c.cache.Open(r.Context(), c.cacheKey(r))
	if err == nil {
		headers = codeArtifactOriginHeaders(headers)
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
	cacheHeaders, createOptions, cacheable := codeArtifactCacheEntry(responseHeaders)
	if !cacheable {
		c.metric.recordCache(r.Context(), codeArtifactCacheUnsupportedValidator)
		c.streamOriginBody(r.Context(), w, resp.Body)
		return
	}

	writer, err := c.cache.Create(r.Context(), c.cacheKey(r), cacheHeaders, 0, createOptions...)
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

func codeArtifactCacheEntry(headers http.Header) (http.Header, []cache.Option, bool) {
	cacheHeaders := maps.Clone(headers)
	validators := make([]string, 0, 2)
	var createOptions []cache.Option
	etag := cacheHeaders.Get(cache.ETagKey)
	if etag != "" {
		rawETag, err := cache.RawETagFromHeader(etag)
		if err != nil {
			return nil, nil, false
		}
		validators = append(validators, "etag")
		createOptions = []cache.Option{cache.WithETag(rawETag)}
	}
	if cacheHeaders.Get("Last-Modified") != "" {
		validators = append(validators, "last-modified")
	}
	cacheHeaders.Set(codeArtifactOriginValidatorsHeader, strings.Join(validators, ","))
	return cacheHeaders, createOptions, true
}

func codeArtifactOriginHeaders(headers http.Header) http.Header {
	originHeaders := maps.Clone(headers)
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
		if strings.TrimSpace(value) == want {
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
