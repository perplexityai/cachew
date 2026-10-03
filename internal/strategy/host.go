package strategy

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/strategy/handler"
)

func RegisterHost(r *Registry) {
	Register(r, "host", "A generic host-based proxying strategy.", NewHost)
}

// HostConfig represents the configuration for the Host strategy.
//
// In HCL it looks something like this:
//
//	host {
//		target = "https://github.com/"
//	}
//
// In this example, the strategy will be mounted under "/github.com".
type HostConfig struct {
	Target               string            `hcl:"target,label" help:"The target URL to proxy requests to."`
	Headers              map[string]string `hcl:"headers,optional" help:"Headers to add to upstream requests."`
	OriginHeaderTimeout  time.Duration     `hcl:"origin-header-timeout,optional" help:"Maximum wait for origin response headers. Zero preserves unlimited waiting; response bodies are not time limited."`
	HTTP2ReadIdleTimeout time.Duration     `hcl:"http2-read-idle-timeout,optional" help:"Send a health-check ping after this interval without receiving HTTP/2 frames. Zero disables health checks."`
	HTTP2PingTimeout     time.Duration     `hcl:"http2-ping-timeout,optional" help:"Close an HTTP/2 connection if a health-check ping receives no response within this interval. Zero uses Go's default."`
}

// The Host [Strategy] forwards all GET requests to the specified host, caching the response payloads.
type Host struct {
	target  *url.URL
	cache   cache.Cache
	client  *http.Client
	prefix  string
	headers map[string]string
}

var _ Strategy = (*Host)(nil)

func NewHost(_ context.Context, config HostConfig, cache cache.Cache, mux Mux) (*Host, error) {
	if config.OriginHeaderTimeout < 0 || config.HTTP2ReadIdleTimeout < 0 || config.HTTP2PingTimeout < 0 {
		return nil, errors.New("host transport timeouts must not be negative")
	}
	u, err := url.Parse(config.Target)
	if err != nil {
		return nil, errors.Errorf("invalid target URL: %w", err)
	}
	prefix := "/" + u.Host + u.EscapedPath()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = config.OriginHeaderTimeout
	transport.HTTP2 = &http.HTTP2Config{
		SendPingTimeout: config.HTTP2ReadIdleTimeout,
		PingTimeout:     config.HTTP2PingTimeout,
	}
	h := &Host{
		target:  u,
		cache:   cache,
		client:  &http.Client{Transport: transport},
		prefix:  prefix,
		headers: config.Headers,
	}

	hdlr := handler.New(h.client, cache).
		CacheKey(func(r *http.Request) string {
			return h.buildTargetURL(r).String()
		}).
		Transform(func(r *http.Request) (*http.Request, error) {
			targetURL := h.buildTargetURL(r)
			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL.String(), nil)
			if err != nil {
				return nil, errors.Wrap(err, "creating upstream request")
			}
			for k, v := range h.headers {
				req.Header.Set(k, v)
			}
			return req, nil
		})

	mux.Handle("GET "+prefix+"/", hdlr)
	return h, nil
}

func (d *Host) String() string { return "host:" + d.target.Host + d.target.Path }

// buildTargetURL constructs the target URL from the incoming request.
func (d *Host) buildTargetURL(r *http.Request) *url.URL {
	// Strip the prefix from the request path
	path := r.URL.Path
	if len(path) >= len(d.prefix) {
		path = path[len(d.prefix):]
	}
	if path == "" {
		path = "/"
	}

	targetURL := *d.target
	targetURL.Path = path
	targetURL.RawQuery = r.URL.RawQuery
	return &targetURL
}
