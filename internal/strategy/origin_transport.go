package strategy

import (
	"context"
	"net"

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
