package strategy

import (
	"bytes"
	"context"
	"io"
	"net/http"
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
	reusable    bool
}

type npmMetadataCache struct {
	ctx          context.Context
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
		if parts := npmMetadataPath.FindStringSubmatch("/npm/" + repo + "/package"); len(parts) != 3 || parts[1] != repo {
			return errors.Errorf("npm-metadata-cache: invalid repository %q", repo)
		}
	}
	return nil
}

func newNPMMetadataCache(ctx context.Context, config *NPMMetadataCacheConfig) *npmMetadataCache {
	if config == nil {
		return nil
	}
	c := &npmMetadataCache{ctx: ctx, config: *config, repositories: map[string]bool{}, entries: map[string]*npmMetadataResponse{}, flights: map[string]*npmMetadataFlight{}}
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
	parts := npmMetadataPath.FindStringSubmatch(origin.EscapedPath())
	if len(parts) != 3 || !m.repositories[parts[1]] {
		return false
	}
	bypass := false
	for _, name := range []string{"Cookie", "Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		bypass = bypass || len(r.Header.Values(name)) != 0
	}
	directives, ok := parseCodeArtifactCacheControl(r.Header.Values("Cache-Control"))
	_, noStore := directives["no-store"]
	if bypass || !ok || noStore {
		c.serveOrigin(w, r, codeArtifactCachePassthrough)
		return true
	}
	force := len(directives) != 0 || r.Header.Get("Pragma") != ""
	key := origin.String() + "\nAccept=" + strings.Join(r.Header.Values("Accept"), ",") + "\nGzip=" + strconv.FormatBool(codeArtifactGzipAccepted(r.Header))
	for {
		response, flight, owner, busy := m.lookup(key, origin.Scheme+"://"+origin.Host+origin.Path, force)
		if busy {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "metadata fetch capacity exhausted", http.StatusServiceUnavailable)
			return true
		}
		if response != nil {
			if err := response.serve(w); err != nil {
				c.logger.ErrorContext(r.Context(), "Failed to serve npm metadata", "error", err)
			}
			return true
		}
		if owner {
			request := r.Clone(m.ctx)
			go c.fillNPMMetadata(key, request, flight)
		}
		select {
		case <-r.Context().Done():
			return true
		case <-flight.done:
			if owner || (flight.reusable && time.Now().Before(flight.response.expires)) {
				if err := flight.response.serve(w); err != nil {
					c.logger.ErrorContext(r.Context(), "Failed to serve npm metadata", "error", err)
				}
				return true
			}
		}
	}
}

func (m *npmMetadataCache) lookup(key, resource string, force bool) (*npmMetadataResponse, *npmMetadataFlight, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.entries[key]; entry != nil {
		if !force && time.Now().Before(entry.expires) {
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
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	capture := &npmMetadataCapture{headers: make(http.Header)}
	c.serveOrigin(capture, r.WithContext(ctx), codeArtifactCachePassthrough)
	response := &npmMetadataResponse{headers: capture.headers.Clone(), status: capture.status, body: bytes.Clone(capture.body.Bytes()), stored: time.Now()}
	if response.status == 0 {
		response.status = http.StatusOK
	}
	if capture.failed {
		response = &npmMetadataResponse{headers: make(http.Header), status: http.StatusBadGateway, body: []byte("metadata response exceeds size limit\n"), stored: time.Now()}
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
	reusable := response.status == http.StatusOK && time.Now().Before(response.expires) && response.size <= m.config.MaxBytes && !capture.failed
	m.complete(key, flight, response, reusable)
}

func (m *npmMetadataCache) complete(key string, flight *npmMetadataFlight, response *npmMetadataResponse, reusable bool) {
	m.mu.Lock()
	if response.status == http.StatusUnauthorized || response.status == http.StatusForbidden || response.status == http.StatusNotFound {
		m.invalidate(response.resource)
	}
	reusable = reusable && !flight.invalidated
	if reusable {
		for key, entry := range m.entries {
			if !time.Now().Before(entry.expires) {
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
		}
		m.entries[key] = response
		m.bytes += response.size
	}
	flight.response, flight.reusable = response, reusable
	delete(m.flights, key)
	close(flight.done)
	m.mu.Unlock()
}

func (m *npmMetadataCache) invalidate(resource string) {
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

func npmMetadataExpiry(response *npmMetadataResponse, started time.Time, ttl time.Duration) time.Time {
	headers := response.headers
	directives, ok := parseCodeArtifactCacheControl(headers.Values("Cache-Control"))
	if !ok || headers.Get("Set-Cookie") != "" || !supportedCodeArtifactVary(headers.Values("Vary")) {
		return time.Time{}
	}
	for _, name := range []string{"private", "no-cache", "no-store"} {
		if _, found := directives[name]; found {
			return time.Time{}
		}
	}
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

func (r *npmMetadataResponse) serve(w http.ResponseWriter) error {
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
	headers.Set("Age", strconv.FormatInt(max(0, age)+max(0, int64(time.Since(r.stored)/time.Second)), 10))
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
	if w.body.Len()+len(body) > maxCodeArtifactMetadataBytes {
		w.failed = true
		return 0, io.ErrShortBuffer
	}
	n, err := w.body.Write(body)
	return n, errors.Wrap(err, "capture npm metadata")
}
