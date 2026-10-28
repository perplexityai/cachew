package strategy

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/alecthomas/errors"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type codeArtifactStreamReader struct {
	reader io.Reader
	bytes  int64
	err    error
}

func (r *codeArtifactStreamReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		r.err = err
	}
	return n, err //nolint:wrapcheck // Preserve EOF and the underlying error for stream classification.
}

func (c *CodeArtifact) streamOriginBody(w http.ResponseWriter, r *http.Request, body io.Reader) {
	started := time.Now()
	reader := &codeArtifactStreamReader{reader: body}
	written, err := io.Copy(w, reader)
	if err != nil {
		c.abortStream(w, r, "origin", reader, written, started, err)
	}
}

func (c *CodeArtifact) abortStream(w http.ResponseWriter, r *http.Request, source string,
	reader *codeArtifactStreamReader, written int64, started time.Time, err error,
) {
	stage := "client_write"
	if reader.err != nil && errors.Is(err, reader.err) {
		stage = "source_read"
	}
	expected := int64(-1)
	if n, parseErr := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64); parseErr == nil && n >= 0 {
		expected = n
	}
	kind := codeArtifactBodyError(r.Context(), err)
	format := codeArtifactMetricFormat(c.originURL(r).Path)
	clientCanceled := errors.Is(r.Context().Err(), context.Canceled) || errors.Is(err, context.Canceled)
	if !clientCanceled {
		trace.SpanFromContext(r.Context()).SetStatus(codes.Error, kind)
	}
	if c.metric != nil {
		c.metric.recordStreamFailure(context.WithoutCancel(r.Context()), stage, kind, format)
	}
	c.logger.ErrorContext(r.Context(), "CodeArtifact response stream failed",
		"source", source, "stage", stage, "error_kind", kind,
		"format", format, "bytes_read", reader.bytes, "bytes_written", written,
		"expected_bytes", expected, "duration_ms", time.Since(started).Milliseconds(), "client_canceled", clientCanceled)
	// Headers are already committed. Returning normally would terminate a chunked
	// body successfully and disguise a failed read as a complete response.
	panic(http.ErrAbortHandler)
}

func codeArtifactBodyError(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errCodeArtifactOriginReadIdleTimeout):
		return "read_idle_timeout"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, io.ErrShortWrite):
		return "short_write"
	case errors.Is(err, context.Canceled):
		return "client_canceled"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken_pipe"
	default:
		return codeArtifactTransportStatus(ctx, err)
	}
}
