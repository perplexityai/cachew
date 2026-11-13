package strategy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/alecthomas/errors"
)

// originTransportStatus names why an origin request failed before response
// headers, from a fixed set suitable for a metric label.
func originTransportStatus(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.Canceled) {
		return "client_canceled"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "transport_dns"
	}
	var timeoutErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeoutErr) && timeoutErr.Timeout()) {
		return "transport_timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "transport_connection"
	}
	return "transport_error"
}

// newTunedOriginTransport returns a transport with net/http's default settings
// for an origin that needs its own compression and header timeout, independent
// of the process-wide default and shared upstream transport.
func newTunedOriginTransport(headerTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Proxy origin bytes as sent so cached bodies keep their encoding.
		DisableCompression:    true,
		ResponseHeaderTimeout: headerTimeout,
	}
}
