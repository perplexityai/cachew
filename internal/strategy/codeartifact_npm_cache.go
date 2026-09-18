package strategy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

// NPMMetadataCacheConfig opts a set of repositories into bounded local metadata caching.
type NPMMetadataCacheConfig struct {
	Repositories  []string      `hcl:"repositories" help:"CodeArtifact npm repository names whose package metadata may be cached."`
	TTL           time.Duration `hcl:"ttl" help:"Maximum metadata staleness, from 1s through 5m."`
	MaxBytes      int           `hcl:"max-bytes" help:"Maximum retained metadata bytes, from 1MiB through 1GiB."`
	MaxConcurrent int           `hcl:"max-concurrent,optional" help:"Maximum concurrent metadata fills; default 4, maximum 32."`
}

var npmMetadataRoutingSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

var npmMetadataPath = regexp.MustCompile(`^/npm/([A-Za-z0-9][A-Za-z0-9._-]*)/((?:@[a-z0-9][a-z0-9._-]*(?:/|%2[fF]))?[a-z0-9][a-z0-9._-]*)$`)

type npmMetadataResponse struct {
	resource string
	headers  http.Header
	status   int
	body     []byte
	expires  time.Time
	stored   time.Time
	size     int
}

type npmMetadataFlight struct {
	resource    string
	invalidated bool
	done        chan struct{}
	response    *npmMetadataResponse
	shareable   bool
}

type npmMetadataCache struct {
	ctx          context.Context
	now          func() time.Time
	config       NPMMetadataCacheConfig
	repositories map[string]bool
	mu           sync.Mutex
	entries      map[string]*npmMetadataResponse
	flights      map[string]*npmMetadataFlight
	bytes        int
}

func validateNPMMetadataCache(config *NPMMetadataCacheConfig) error {
	if config == nil {
		return nil
	}
	if config.TTL < time.Second || config.TTL > 5*time.Minute {
		return errors.New("npm-metadata-cache: ttl must be between 1s and 5m")
	}
	if config.MaxBytes < 1<<20 || config.MaxBytes > 1<<30 {
		return errors.New("npm-metadata-cache: max-bytes must be between 1MiB and 1GiB")
	}
	if config.MaxConcurrent < 0 || config.MaxConcurrent > 32 {
		return errors.New("npm-metadata-cache: max-concurrent must be between 1 and 32, or zero for the default")
	}
	if len(config.Repositories) == 0 {
		return errors.New("npm-metadata-cache: repositories must not be empty")
	}
	for _, repo := range config.Repositories {
		if !npmMetadataRoutingSegment.MatchString(repo) {
			return errors.Errorf("npm-metadata-cache: invalid repository %q", repo)
		}
	}
	return nil
}

func newNPMMetadataCache(ctx context.Context, config *NPMMetadataCacheConfig) *npmMetadataCache {
	if config == nil {
		return nil
	}
	c := &npmMetadataCache{ctx: ctx, now: time.Now, config: *config, repositories: map[string]bool{}, entries: map[string]*npmMetadataResponse{}, flights: map[string]*npmMetadataFlight{}}
	if c.config.MaxConcurrent == 0 {
		c.config.MaxConcurrent = 4
	}
	for _, repo := range config.Repositories {
		c.repositories[repo] = true
	}
	return c
}

func (c *CodeArtifact) serveNPMMetadata(w http.ResponseWriter, r *http.Request) bool {
	m := c.npmMetadata
	if m == nil || r.Method != http.MethodGet || r.URL.RawQuery != "" {
		return false
	}
	origin := c.originURL(r)
	if !m.repositories[npmMetadataRepository(origin)] {
		return false
	}
	resource := origin.Scheme + "://" + origin.Host + origin.Path
	key := origin.String() + "\nAccept=" + strings.Join(r.Header.Values("Accept"), ",") + "\nGzip=" + strconv.FormatBool(codeArtifactGzipAccepted(r.Header))
	bypass := false
	for _, name := range []string{"Cookie", "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		bypass = bypass || len(r.Header.Values(name)) != 0
	}
	directives, ok := parseCodeArtifactCacheControl(r.Header.Values("Cache-Control"))
	_, noStore := directives["no-store"]
	_, noCache := directives["no-cache"]
	force := len(directives) != 0 || r.Header.Get("Pragma") != ""
	if bypass || !ok || noStore {
		c.metric.recordCache(r.Context(), codeArtifactCacheBypass, codeArtifactCacheTierNPMMetadata)
		if force && (!noStore || noCache || directives["max-age"] == "0") {
			m.forget(key)
		}
		c.serveOrigin(&npmMetadataInvalidationWriter{ResponseWriter: w, cache: m, resource: resource}, r, codeArtifactCachePassthrough)
		return true
	}
	waitLimit := time.NewTimer(time.Minute)
	defer waitLimit.Stop()
	for {
		response, flight, owner, busy := m.lookup(key, resource, force)
		if busy {
			c.metric.recordCache(r.Context(), codeArtifactCacheCapacityRejected, codeArtifactCacheTierNPMMetadata)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "metadata fetch capacity exhausted", http.StatusServiceUnavailable)
			return true
		}
		if response != nil {
			c.metric.recordCache(r.Context(), codeArtifactCacheHit, codeArtifactCacheTierNPMMetadata)
			if err := response.serve(w, m.now()); err != nil {
				c.logger.ErrorContext(r.Context(), "Failed to serve npm metadata", "error", err)
			}
			return true
		}
		if owner {
			c.metric.recordCache(r.Context(), codeArtifactCacheMiss, codeArtifactCacheTierNPMMetadata)
			request := r.Clone(m.ctx)
			go c.fillNPMMetadata(key, request, flight)
		} else {
			c.metric.recordCache(r.Context(), codeArtifactCacheCoalesced, codeArtifactCacheTierNPMMetadata)
		}
		select {
		case <-r.Context().Done():
			return true
		case <-waitLimit.C:
			c.metric.recordCache(r.Context(), codeArtifactCacheWaitTimeout, codeArtifactCacheTierNPMMetadata)
			http.Error(w, "metadata fetch wait timed out", http.StatusGatewayTimeout)
			return true
		case <-flight.done:
			if owner || flight.shareable {
				if err := flight.response.serve(w, m.now()); err != nil {
					c.logger.ErrorContext(r.Context(), "Failed to serve npm metadata", "error", err)
				}
				return true
			}
		}
	}
}

func npmMetadataRepository(origin url.URL) string {
	path := origin.EscapedPath()
	host := strings.ToLower(origin.Hostname())
	if strings.HasSuffix(host, ".vpce.amazonaws.com") || strings.HasSuffix(host, ".vpce.amazonaws.com.cn") {
		remainder, ok := strings.CutPrefix(path, "/npm/d/")
		if !ok {
			return ""
		}
		domain, packagePath, ok := strings.Cut(remainder, "/")
		if !ok || !npmMetadataRoutingSegment.MatchString(domain) {
			return ""
		}
		path = "/npm/" + packagePath
	}
	parts := npmMetadataPath.FindStringSubmatch(path)
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

type npmMetadataInvalidationWriter struct {
	http.ResponseWriter
	cache    *npmMetadataCache
	resource string
}

func (w *npmMetadataInvalidationWriter) WriteHeader(status int) {
	if npmMetadataAuthoritativeFailure(status) {
		w.cache.invalidateResource(w.resource)
	}
	w.ResponseWriter.WriteHeader(status)
}

func npmMetadataAuthoritativeFailure(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

func (m *npmMetadataCache) forget(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remove(key)
	if flight := m.flights[key]; flight != nil {
		flight.invalidated = true
	}
}

func (m *npmMetadataCache) lookup(key, resource string, force bool) (*npmMetadataResponse, *npmMetadataFlight, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.entries[key]; entry != nil {
		if !force && m.now().Before(entry.expires) {
			return entry, nil, false, false
		}
		m.remove(key)
	}
	if flight := m.flights[key]; flight != nil {
		return nil, flight, false, false
	}
	if len(m.flights) >= m.config.MaxConcurrent {
		return nil, nil, false, true
	}
	flight := &npmMetadataFlight{done: make(chan struct{}), resource: resource}
	m.flights[key] = flight
	return nil, flight, true, false
}

func (c *CodeArtifact) fillNPMMetadata(key string, r *http.Request, flight *npmMetadataFlight) {
	m := c.npmMetadata
	started := m.now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	capture := &npmMetadataCapture{headers: make(http.Header)}
	c.serveOrigin(capture, r.WithContext(ctx), codeArtifactCachePassthrough)
	response := &npmMetadataResponse{headers: capture.headers.Clone(), status: capture.status, body: capture.body.Bytes(), stored: m.now()}
	if response.status == 0 {
		response.status = http.StatusOK
	}
	if capture.failed {
		response = &npmMetadataResponse{headers: make(http.Header), status: http.StatusBadGateway, body: []byte("metadata error response exceeds size limit\n"), stored: m.now()}
	}
	response.resource = flight.resource
	response.expires = npmMetadataExpiry(response, started, m.config.TTL)
	response.size = len(response.body) + len(key)
	for name, values := range response.headers {
		response.size += len(name)
		for _, value := range values {
			response.size += len(value)
		}
	}
	reusable := response.status == http.StatusOK && m.now().Before(response.expires) && response.size <= m.config.MaxBytes && !capture.failed
	if reusable {
		response.body = bytes.Clone(response.body)
	}
	c.completeNPMMetadata(key, flight, response, reusable)
}

func (c *CodeArtifact) completeNPMMetadata(key string, flight *npmMetadataFlight, response *npmMetadataResponse, reusable bool) {
	m := c.npmMetadata
	m.mu.Lock()
	if npmMetadataAuthoritativeFailure(response.status) {
		m.invalidateLocked(response.resource)
	}
	reusable = reusable && !flight.invalidated
	if reusable {
		for key, entry := range m.entries {
			if !m.now().Before(entry.expires) {
				m.remove(key)
			}
		}
		for m.bytes+response.size > m.config.MaxBytes || len(m.entries) >= 1024 {
			var oldest string
			var expires time.Time
			for key, entry := range m.entries {
				if oldest == "" || entry.expires.Before(expires) {
					oldest, expires = key, entry.expires
				}
			}
			m.remove(oldest)
			c.metric.recordCache(m.ctx, codeArtifactCacheEvicted, codeArtifactCacheTierNPMMetadata)
		}
		m.entries[key] = response
		m.bytes += response.size
		c.metric.recordCache(m.ctx, codeArtifactCacheStored, codeArtifactCacheTierNPMMetadata)
	} else {
		c.metric.recordCache(m.ctx, codeArtifactCacheNotCacheable, codeArtifactCacheTierNPMMetadata)
	}
	flight.response = response
	flight.shareable = npmMetadataShareable(response) && (!flight.invalidated || response.status >= 400)
	delete(m.flights, key)
	close(flight.done)
	m.mu.Unlock()
}

func (m *npmMetadataCache) invalidateResource(resource string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateLocked(resource)
}

func (m *npmMetadataCache) invalidateLocked(resource string) {
	for key, entry := range m.entries {
		if entry.resource == resource {
			m.remove(key)
		}
	}
	for _, flight := range m.flights {
		if flight.resource == resource {
			flight.invalidated = true
		}
	}
}

func (m *npmMetadataCache) remove(key string) {
	if entry := m.entries[key]; entry != nil {
		m.bytes -= entry.size
		delete(m.entries, key)
	}
}

func npmMetadataShareable(response *npmMetadataResponse) bool {
	if response.status == http.StatusOK {
		return !response.expires.IsZero()
	}
	return response.status >= 400 && npmMetadataAllowsSharing(response.headers)
}

func npmMetadataAllowsSharing(headers http.Header) bool {
	directives, ok := parseCodeArtifactCacheControl(headers.Values("Cache-Control"))
	if !ok || headers.Get("Set-Cookie") != "" || !supportedCodeArtifactVary(headers.Values("Vary")) {
		return false
	}
	for _, name := range []string{"private", "no-cache", "no-store"} {
		if _, found := directives[name]; found {
			return false
		}
	}
	return true
}

func npmMetadataExpiry(response *npmMetadataResponse, started time.Time, ttl time.Duration) time.Time {
	headers := response.headers
	if !npmMetadataAllowsSharing(headers) {
		return time.Time{}
	}
	directives, _ := parseCodeArtifactCacheControl(headers.Values("Cache-Control"))
	_, maxAge := directives["max-age"]
	_, sharedAge := directives["s-maxage"]
	if !maxAge && !sharedAge {
		if headers.Get("Expires") != "" {
			expires, err := http.ParseTime(headers.Get("Expires"))
			if err != nil {
				return time.Time{}
			}
			date, err := http.ParseTime(headers.Get("Date"))
			if err != nil {
				return time.Time{}
			}
			directives["max-age"] = strconv.FormatInt(int64(expires.Sub(date)/time.Second), 10)
		} else {
			directives["max-age"] = strconv.FormatInt(int64(ttl/time.Second), 10)
		}
	}
	remaining, ok := codeArtifactFreshnessLifetime(headers, directives, response.stored)
	if !ok {
		return time.Time{}
	}
	localRemaining, ok := codeArtifactFreshnessLifetime(headers, map[string]string{"max-age": strconv.FormatInt(int64(ttl/time.Second), 10)}, response.stored)
	if !ok {
		return time.Time{}
	}
	return minTime(started.Add(localRemaining), started.Add(remaining))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *npmMetadataResponse) serve(w http.ResponseWriter, now time.Time) error {
	headers := r.headers.Clone()
	if r.status == http.StatusOK && !r.expires.IsZero() {
		headers.Set("Cache-Control", "private, no-cache")
		headers.Del("Expires")
	}
	age, err := strconv.ParseInt(headers.Get("Age"), 10, 64)
	if err != nil {
		age = 0
	}
	if date, err := http.ParseTime(headers.Get("Date")); err == nil {
		age = max(age, int64(r.stored.Sub(date)/time.Second))
	}
	headers.Set("Age", strconv.FormatInt(max(0, age)+max(0, int64(now.Sub(r.stored)/time.Second)), 10))
	copyHeaders(w.Header(), headers)
	w.WriteHeader(r.status)
	_, err = w.Write(r.body) //nolint:gosec // G705: proxy responses retain their content type; successful metadata is validated JSON.
	return errors.Wrap(err, "write npm metadata")
}

type npmMetadataCapture struct {
	headers http.Header
	status  int
	body    bytes.Buffer
	failed  bool
}

func (w *npmMetadataCapture) Header() http.Header { return w.headers }
func (w *npmMetadataCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *npmMetadataCapture) Write(body []byte) (int, error) {
	if w.status != http.StatusOK && w.body.Len()+len(body) > maxCodeArtifactMetadataBytes {
		w.failed = true
		return 0, io.ErrShortBuffer
	}
	n, err := w.body.Write(body)
	return n, errors.Wrap(err, "capture npm metadata")
}
