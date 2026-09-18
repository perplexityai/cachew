package strategy

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

// MetadataCacheConfig opts a set of repositories into bounded local metadata caching.
type MetadataCacheConfig struct {
	Repositories  []string      `hcl:"repositories" help:"Repository names to cache, or a single * for all repositories at this origin."`
	Formats       []string      `hcl:"formats" help:"Metadata formats to cache: npm, pypi, cargo, swift."`
	TTL           time.Duration `hcl:"ttl" help:"Maximum metadata staleness, from 1s through 5m."`
	MaxBytes      int           `hcl:"max-bytes" help:"Maximum retained metadata bytes, from 1MiB through 1GiB."`
	MaxConcurrent int           `hcl:"max-concurrent,optional" help:"Maximum concurrent metadata fills; default 4, maximum 32."`
}

type metadataResponse struct {
	resource string
	headers  http.Header
	status   int
	body     *metadataBody
	expires  time.Time
	stored   time.Time
	size     int
}

type metadataFlight struct {
	resource    string
	invalidated bool
	done        chan struct{}
	response    *metadataResponse
	shareable   bool
	waiters     int
}

type metadataCache struct {
	ctx          context.Context
	now          func() time.Time
	config       MetadataCacheConfig
	repositories map[string]bool
	formats      map[string]bool
	mu           sync.Mutex
	entries      map[string]*metadataResponse
	flights      map[string]*metadataFlight
	bytes        int
}

func validateMetadataCache(config *MetadataCacheConfig) error {
	if config == nil {
		return nil
	}
	if config.TTL < time.Second || config.TTL > 5*time.Minute {
		return errors.New("metadata-cache: ttl must be between 1s and 5m")
	}
	if config.MaxBytes < 1<<20 || config.MaxBytes > 1<<30 {
		return errors.New("metadata-cache: max-bytes must be between 1MiB and 1GiB")
	}
	if config.MaxConcurrent < 0 || config.MaxConcurrent > 32 {
		return errors.New("metadata-cache: max-concurrent must be between 1 and 32, or zero for the default")
	}
	if len(config.Repositories) == 0 {
		return errors.New("metadata-cache: repositories must not be empty")
	}
	for _, repo := range config.Repositories {
		if repo == "*" && len(config.Repositories) == 1 {
			continue
		}
		if !metadataRoutingSegment.MatchString(repo) {
			return errors.Errorf("metadata-cache: invalid repository %q", repo)
		}
	}
	if len(config.Formats) == 0 {
		return errors.New("metadata-cache: formats must not be empty")
	}
	for _, format := range config.Formats {
		if metadataFormatClassifier(format) == nil {
			return errors.Errorf("metadata-cache: unsupported format %q", format)
		}
	}
	return nil
}

func newMetadataCache(ctx context.Context, config *MetadataCacheConfig) *metadataCache {
	if config == nil {
		return nil
	}
	c := &metadataCache{ctx: ctx, now: time.Now, config: *config, repositories: map[string]bool{}, formats: map[string]bool{}, entries: map[string]*metadataResponse{}, flights: map[string]*metadataFlight{}}
	if c.config.MaxConcurrent == 0 {
		c.config.MaxConcurrent = 4
	}
	for _, repo := range config.Repositories {
		c.repositories[repo] = true
	}
	for _, format := range config.Formats {
		c.formats[format] = true
	}
	return c
}

func (c *CodeArtifact) serveMetadata(w http.ResponseWriter, r *http.Request) bool {
	m := c.metadata
	if m == nil || r.Method != http.MethodGet || r.URL.RawQuery != "" {
		return false
	}
	origin := c.originURL(r)
	route, ok := classifyMetadataRoute(origin)
	if !ok || !m.formats[route.format] || (!m.repositories["*"] && !m.repositories[route.repository]) {
		return false
	}
	resource := origin.Scheme + "://" + origin.Host + origin.Path
	key := origin.String() + "\nAccept=" + strings.Join(r.Header.Values("Accept"), ",") + "\nAccept-Encoding=" + strings.Join(r.Header.Values("Accept-Encoding"), ",")
	bypass := false
	for _, name := range []string{"Cookie", "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		bypass = bypass || len(r.Header.Values(name)) != 0
	}
	directives, ok := parseCodeArtifactCacheControl(r.Header.Values("Cache-Control"))
	_, noStore := directives["no-store"]
	_, noCache := directives["no-cache"]
	force := len(directives) != 0 || r.Header.Get("Pragma") != ""
	if bypass || !ok || noStore {
		c.metric.recordCache(r.Context(), codeArtifactCacheBypass, codeArtifactCacheTierMetadata)
		if force && (!noStore || noCache || directives["max-age"] == "0") {
			m.forget(key)
		}
		c.serveOrigin(&metadataInvalidationWriter{ResponseWriter: w, cache: m, resource: resource}, r, codeArtifactCachePassthrough)
		return true
	}
	waitLimit := time.NewTimer(time.Minute)
	defer waitLimit.Stop()
	for {
		response, flight, owner, busy := m.lookup(key, resource, force)
		if busy {
			c.metric.recordCache(r.Context(), codeArtifactCacheCapacityRejected, codeArtifactCacheTierMetadata)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "metadata fetch capacity exhausted", http.StatusServiceUnavailable)
			return true
		}
		if response != nil {
			c.metric.recordCache(r.Context(), codeArtifactCacheHit, codeArtifactCacheTierMetadata)
			if err := response.serve(w, m.now()); err != nil {
				c.logger.ErrorContext(r.Context(), "Failed to serve package metadata", "error", err)
			}
			return true
		}
		if owner {
			c.metric.recordCache(r.Context(), codeArtifactCacheMiss, codeArtifactCacheTierMetadata)
			request := r.Clone(m.ctx)
			go c.fillMetadata(key, request, flight, route)
		} else {
			c.metric.recordCache(r.Context(), codeArtifactCacheCoalesced, codeArtifactCacheTierMetadata)
		}
		if c.serveMetadataFlight(w, r, flight, owner, waitLimit.C) {
			return true
		}
	}
}

func (c *CodeArtifact) serveMetadataFlight(w http.ResponseWriter, r *http.Request, flight *metadataFlight, owner bool, deadline <-chan time.Time) bool {
	defer func() {
		if err := c.metadata.release(flight); err != nil {
			c.logger.ErrorContext(r.Context(), "Failed to close metadata spool", "error", err)
		}
	}()
	select {
	case <-r.Context().Done():
		return true
	case <-deadline:
		c.metric.recordCache(r.Context(), codeArtifactCacheWaitTimeout, codeArtifactCacheTierMetadata)
		http.Error(w, "metadata fetch wait timed out", http.StatusGatewayTimeout)
		return true
	case <-flight.done:
		if !owner && !flight.shareable {
			return false
		}
		if err := flight.response.serve(w, c.metadata.now()); err != nil {
			c.logger.ErrorContext(r.Context(), "Failed to serve package metadata", "error", err)
		}
		return true
	}
}

func (m *metadataCache) release(flight *metadataFlight) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	flight.waiters--
	if flight.waiters == 0 && flight.response != nil {
		return flight.response.body.close()
	}
	return nil
}

type metadataInvalidationWriter struct {
	http.ResponseWriter
	cache    *metadataCache
	resource string
}

func (w *metadataInvalidationWriter) WriteHeader(status int) {
	if metadataAuthoritativeFailure(status) {
		w.cache.invalidateResource(w.resource)
	}
	w.ResponseWriter.WriteHeader(status)
}

func metadataAuthoritativeFailure(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusGone || status == http.StatusUnavailableForLegalReasons
}

func (m *metadataCache) forget(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remove(key)
	if flight := m.flights[key]; flight != nil {
		flight.invalidated = true
	}
}

func (m *metadataCache) lookup(key, resource string, force bool) (*metadataResponse, *metadataFlight, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.entries[key]; entry != nil {
		if !force && m.now().Before(entry.expires) {
			return entry, nil, false, false
		}
		m.remove(key)
	}
	if flight := m.flights[key]; flight != nil {
		flight.waiters++
		return nil, flight, false, false
	}
	if len(m.flights) >= m.config.MaxConcurrent {
		return nil, nil, false, true
	}
	flight := &metadataFlight{done: make(chan struct{}), resource: resource, waiters: 1}
	m.flights[key] = flight
	return nil, flight, true, false
}

func (c *CodeArtifact) fillMetadata(key string, r *http.Request, flight *metadataFlight, route metadataRoute) {
	m := c.metadata
	started := m.now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	capture := &metadataCapture{headers: make(http.Header)}
	writer := &metadataInvalidationWriter{ResponseWriter: capture, cache: m, resource: flight.resource}
	err := c.writeOrigin(writer, r.WithContext(ctx), codeArtifactCachePassthrough)
	body, finishErr := capture.finish(m.config.MaxBytes)
	err = errors.Join(err, finishErr)
	response := &metadataResponse{headers: capture.headers.Clone(), status: capture.status, body: body, stored: m.now()}
	if err != nil {
		if closeErr := body.close(); closeErr != nil {
			c.logger.ErrorContext(ctx, "Failed to close metadata spool", "error", closeErr)
		}
		c.logger.ErrorContext(ctx, "Failed to fetch complete metadata", "error", err)
		response = &metadataResponse{headers: make(http.Header), status: http.StatusBadGateway, body: &metadataBody{data: []byte("incomplete metadata response\n")}, stored: m.now()}
	}
	response.resource = flight.resource
	if response.status != http.StatusOK || route.acceptsResponse(response.headers) {
		response.expires = metadataExpiry(response, started, m.config.TTL)
	}
	response.size = len(response.body.data) + len(key)
	for name, values := range response.headers {
		response.size += len(name)
		for _, value := range values {
			response.size += len(value)
		}
	}
	reusable := response.status == http.StatusOK && m.now().Before(response.expires) && response.body.file == nil && response.size <= m.config.MaxBytes
	c.completeMetadata(key, flight, response, reusable)
}

func (c *CodeArtifact) completeMetadata(key string, flight *metadataFlight, response *metadataResponse, reusable bool) {
	m := c.metadata
	m.mu.Lock()
	if metadataAuthoritativeFailure(response.status) {
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
			c.metric.recordCache(m.ctx, codeArtifactCacheEvicted, codeArtifactCacheTierMetadata)
		}
		m.entries[key] = response
		m.bytes += response.size
		c.metric.recordCache(m.ctx, codeArtifactCacheStored, codeArtifactCacheTierMetadata)
	} else {
		c.metric.recordCache(m.ctx, codeArtifactCacheNotCacheable, codeArtifactCacheTierMetadata)
	}
	flight.response = response
	flight.shareable = metadataShareable(response) && (!flight.invalidated || response.status >= 400)
	delete(m.flights, key)
	close(flight.done)
	var closeErr error
	if flight.waiters == 0 {
		closeErr = response.body.close()
	}
	m.mu.Unlock()
	if closeErr != nil {
		c.logger.ErrorContext(m.ctx, "Failed to close metadata spool", "error", closeErr)
	}
}

func (m *metadataCache) invalidateResource(resource string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateLocked(resource)
}

func (m *metadataCache) invalidateLocked(resource string) {
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

func (m *metadataCache) remove(key string) {
	if entry := m.entries[key]; entry != nil {
		m.bytes -= entry.size
		delete(m.entries, key)
	}
}

func metadataShareable(response *metadataResponse) bool {
	if response.status == http.StatusOK {
		return !response.expires.IsZero()
	}
	return response.status >= 400 && metadataAllowsSharing(response.headers)
}

func metadataAllowsSharing(headers http.Header) bool {
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

func metadataExpiry(response *metadataResponse, started time.Time, ttl time.Duration) time.Time {
	headers := response.headers
	if !metadataAllowsSharing(headers) {
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

func (r *metadataResponse) serve(w http.ResponseWriter, now time.Time) error {
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
	return r.body.writeTo(w)
}
