package strategy

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
)

const (
	artifactoryStoredAtHeader = "X-Cachew-Artifactory-Stored-At"
	artifactoryETagHeader     = "X-Cachew-Artifactory-Origin-Etag"
	artifactoryModifiedHeader = "X-Cachew-Artifactory-Origin-Modified"
)

func artifactoryCacheRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	for _, name := range []string{"Authorization", "X-JFrog-Art-Api", "Cookie", "Range", "Cache-Control", "Pragma", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		if len(r.Header.Values(name)) != 0 {
			return false
		}
	}
	return true
}

func (a *Artifactory) serveHTTP(w http.ResponseWriter, r *http.Request) {
	key := cache.NewKey("artifactory-policy-v2\n" + a.buildTargetURL(r).String() + "\nAccept=" + strings.Join(r.Header.Values("Accept"), ",") + "\nAccept-Encoding=" + strings.Join(r.Header.Values("Accept-Encoding"), ","))
	eligible := artifactoryCacheRequest(r)
	if eligible {
		served, err := a.serveCached(w, r, key)
		if err != nil {
			a.logger.ErrorContext(r.Context(), "Failed to serve cached Artifactory response", "error", err)
		}
		if served {
			return
		}
	}
	if err := a.serveOrigin(w, r, key, eligible); err != nil {
		a.logger.ErrorContext(r.Context(), "Failed to serve Artifactory response", "error", err)
	}
}

func (a *Artifactory) serveOrigin(w http.ResponseWriter, r *http.Request, key cache.Key, eligible bool) error {
	req, err := a.transformRequest(r)
	if err != nil {
		httputil.ErrorResponse(w, r, http.StatusBadGateway, err.Error())
		return nil
	}
	req.Header = endToEndHeaders(r.Header)
	req.Header.Set("X-Jfrog-Download-Redirect-To", "None")
	started := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		httputil.ErrorResponse(w, r, http.StatusBadGateway, err.Error())
		return nil
	}
	defer resp.Body.Close()
	headers := endToEndHeaders(resp.Header)
	headers.Del(artifactoryStoredAtHeader)
	headers.Del(artifactoryETagHeader)
	headers.Del(artifactoryModifiedHeader)
	headers.Del(cache.ExpirationKey)
	headers.Del("X-Cachew-Result")
	copyHeaders(w.Header(), headers)
	w.Header().Set("X-Cachew-Result", "miss")
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return nil
	}
	ttl, ok := artifactoryFreshness(headers, started, time.Now())
	if !eligible || resp.StatusCode != http.StatusOK || !ok {
		return copyArtifactoryBody(w, resp.Body)
	}
	return a.storeResponse(w, r, key, resp.Body, headers, ttl)
}

func (a *Artifactory) storeResponse(w http.ResponseWriter, r *http.Request, key cache.Key, body io.Reader, headers http.Header, ttl time.Duration) error {
	var options []cache.Option
	if etag := headers.Get("ETag"); etag != "" {
		raw, err := cache.RawETagFromHeader(etag)
		if err != nil {
			return copyArtifactoryBody(w, body)
		}
		options = append(options, cache.WithETag(raw))
	}
	stored := headers.Clone()
	stored.Set(cache.ExpirationKey, time.Now().Add(ttl).UTC().Format(time.RFC3339Nano))
	stored.Set(artifactoryETagHeader, headers.Get("ETag"))
	stored.Set(artifactoryModifiedHeader, headers.Get("Last-Modified"))
	stored.Set(artifactoryStoredAtHeader, time.Now().UTC().Format(time.RFC3339Nano))
	writer, err := a.cache.Create(r.Context(), key, stored, ttl, options...)
	if err != nil {
		return errors.Join(err, copyArtifactoryBody(w, body))
	}
	sink := &bestEffortCacheWriter{writer: writer}
	_, copyErr := io.Copy(w, io.TeeReader(body, sink))
	if copyErr != nil || sink.err != nil {
		return errors.Join(copyErr, sink.err, writer.Abort(errors.Join(copyErr, sink.err)))
	}
	return errors.Wrap(writer.Close(), "commit Artifactory cache entry")
}

func (a *Artifactory) serveCached(w http.ResponseWriter, r *http.Request, key cache.Key) (bool, error) {
	body, headers, err := a.cache.Open(r.Context(), key)
	if err != nil {
		return false, nil
	}
	defer body.Close()
	headers = headers.Clone()
	expires, err := time.Parse(time.RFC3339Nano, headers.Get(cache.ExpirationKey))
	if err != nil || !time.Now().Before(expires) {
		return false, nil
	}
	storedAt, err := time.Parse(time.RFC3339Nano, headers.Get(artifactoryStoredAtHeader))
	if err != nil {
		return false, nil
	}
	age, err := strconv.ParseInt(headers.Get("Age"), 10, 64)
	if err != nil {
		return false, nil
	}
	age += max(0, int64(time.Since(storedAt)/time.Second))
	headers.Set("Age", strconv.FormatInt(age, 10))
	headers.Del(artifactoryStoredAtHeader)
	headers.Del(cache.ExpirationKey)
	for _, pair := range [][2]string{{"ETag", artifactoryETagHeader}, {"Last-Modified", artifactoryModifiedHeader}} {
		headers.Del(pair[0])
		if value := headers.Get(pair[1]); value != "" {
			headers.Set(pair[0], value)
		}
		headers.Del(pair[1])
	}
	copyHeaders(w.Header(), headers)
	w.Header().Set("X-Cachew-Result", "hit")
	return true, copyArtifactoryBody(w, body)
}

func copyArtifactoryBody(w http.ResponseWriter, body io.Reader) error {
	_, err := io.Copy(w, body)
	return errors.Wrap(err, "stream Artifactory response")
}

func artifactoryFreshness(headers http.Header, started, now time.Time) (time.Duration, bool) {
	directives, ok := parseCodeArtifactCacheControl(headers.Values("Cache-Control"))
	if !ok || headers.Get("Set-Cookie") != "" || !supportedCodeArtifactVary(headers.Values("Vary")) {
		return 0, false
	}
	for _, name := range []string{"private", "no-cache", "no-store"} {
		if _, found := directives[name]; found {
			return 0, false
		}
	}
	_, maxAge := directives["max-age"]
	_, sharedAge := directives["s-maxage"]
	if !maxAge && !sharedAge {
		expires, err := http.ParseTime(headers.Get("Expires"))
		if err != nil {
			return 0, false
		}
		date, err := http.ParseTime(headers.Get("Date"))
		if err != nil {
			return 0, false
		}
		directives["max-age"] = strconv.FormatInt(int64(expires.Sub(date)/time.Second), 10)
	}
	ttl, ok := codeArtifactFreshnessLifetime(headers, directives, now)
	if !ok {
		return 0, false
	}
	ttl -= now.Sub(started)
	if ttl <= 0 {
		return 0, false
	}
	age := int64(0)
	if value := headers.Get("Age"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, false
		}
		age = parsed
	}
	if date, err := http.ParseTime(headers.Get("Date")); err == nil {
		age = max(age, int64(now.Sub(date)/time.Second))
	}
	headers.Set("Age", strconv.FormatInt(max(0, age), 10))
	return ttl, true
}
