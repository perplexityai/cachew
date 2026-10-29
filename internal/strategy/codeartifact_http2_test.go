package strategy //nolint:testpackage // Verify private diagnostics without exposing parser internals.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"golang.org/x/net/http2"
)

func TestCodeArtifactGoAwayDetails(t *testing.T) {
	goAway := errors.New(`http2: server sent GOAWAY and closed the connection; LastStreamID=19999, ErrCode=NO_ERROR, debug="private-debug"`)
	typed := http2.GoAwayError{LastStreamID: 19999, ErrCode: http2.ErrCodeNo, DebugData: "private-debug"}
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "stdlib shape", err: goAway},
		{name: "xnet value", err: typed},
		{name: "xnet pointer", err: &typed},
		{name: "wrapped", err: errors.Errorf("private-wrapper: %w", goAway)},
		{name: "stack wrapped", err: errors.WithStack(goAway)},
		{name: "url wrapped", err: &url.Error{Op: "Get", URL: "https://private.example/?token=secret", Err: goAway}},
		{name: "joined first", err: errors.Join(goAway, io.EOF)},
		{name: "joined last", err: errors.Join(io.EOF, errors.Errorf("private-wrapper: %w", goAway))},
	} {
		t.Run(test.name, func(t *testing.T) {
			details, ok := codeArtifactGoAway(test.err)
			assert.True(t, ok)
			assert.Equal(t, codeArtifactGoAwayDetails{code: "NO_ERROR", lastStreamID: 19999}, details)
			assert.Equal(t, "http2_goaway", codeArtifactBodyError(t.Context(), test.err))
		})
	}
}

func TestCodeArtifactGoAwayCodesAndStreamIDs(t *testing.T) {
	for code := http2.ErrCodeNo; code <= http2.ErrCodeHTTP11Required; code++ {
		for _, streamID := range []uint32{0, 19999, 1<<31 - 1} {
			t.Run(fmt.Sprintf("%s/%d", code, streamID), func(t *testing.T) {
				err := http2.GoAwayError{LastStreamID: streamID, ErrCode: code}
				details, ok := codeArtifactGoAway(err)
				assert.True(t, ok)
				assert.Equal(t, codeArtifactGoAwayDetails{code: code.String(), lastStreamID: streamID}, details)
			})
		}
	}
	for _, code := range []http2.ErrCode{14, 255, 1<<32 - 1} {
		details, ok := codeArtifactGoAway(http2.GoAwayError{LastStreamID: 19999, ErrCode: code})
		assert.False(t, ok)
		assert.Equal(t, codeArtifactGoAwayDetails{}, details)
	}
}

func TestCodeArtifactGoAwayMalformedMetadata(t *testing.T) {
	const valid = `http2: server sent GOAWAY and closed the connection; LastStreamID=19999, ErrCode=NO_ERROR, debug=""`
	invalid := []string{
		"",
		"GOAWAY",
		"private-wrapper: " + valid,
		strings.Replace(valid, "http2:", "HTTP2:", 1),
		strings.Replace(valid, "LastStreamID=", "LastStreamID = ", 1),
		strings.Replace(valid, ", ErrCode=", " ErrCode=", 1),
		strings.Replace(valid, ", debug=", ", private=", 1),
		strings.TrimSuffix(valid, `, debug=""`),
		strings.TrimSuffix(valid, `"`),
		strings.TrimSuffix(valid, `""`) + "private-debug",
		valid + "private-suffix",
	}
	for _, streamID := range []string{"", "-1", "+1", "01", " 1", "1 ", "1.0", "0x1", "2147483648", "4294967295", strings.Repeat("9", 1024)} {
		invalid = append(invalid, strings.Replace(valid, "19999", streamID, 1))
	}
	for _, code := range []string{"", "0", "no_error", "NO_ERROR ", "UNKNOWN", "unknown error code 0xff", "NO_ERROR\nprivate", strings.Repeat("X", 1024)} {
		invalid = append(invalid, strings.Replace(valid, "NO_ERROR", code, 1))
	}
	for i, message := range invalid {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			details, ok := codeArtifactGoAway(errors.New(message))
			assert.False(t, ok)
			assert.Equal(t, codeArtifactGoAwayDetails{}, details)
			assert.Equal(t, "transport_error", codeArtifactBodyError(t.Context(), errors.New(message)))
		})
	}
	for _, err := range []error{
		nil,
		codeArtifactDiagnosticWrapperError{message: valid, inner: errors.New("not GOAWAY")},
		errors.New(`private-debug="` + valid + `"`),
		http2.StreamError{StreamID: 19999, Code: http2.ErrCodeCancel},
	} {
		details, ok := codeArtifactGoAway(err)
		assert.False(t, ok)
		assert.Equal(t, codeArtifactGoAwayDetails{}, details)
	}
}

func TestCodeArtifactGoAwayBoundedTraversal(t *testing.T) {
	goAway := http2.GoAwayError{LastStreamID: 19999, ErrCode: http2.ErrCodeNo}
	var wrapped error = goAway
	for range 31 {
		wrapped = codeArtifactDiagnosticWrapperError{inner: wrapped}
	}
	_, ok := codeArtifactGoAway(wrapped)
	assert.True(t, ok)
	wrapped = codeArtifactDiagnosticWrapperError{inner: wrapped}
	_, ok = codeArtifactGoAway(wrapped)
	assert.False(t, ok)

	cycle := &codeArtifactDiagnosticCycleError{}
	_, ok = codeArtifactGoAway(cycle)
	assert.False(t, ok)
	assert.Equal(t, 32, cycle.visits)

	joined := make([]error, 0, 33)
	for range 32 {
		joined = append(joined, errors.New("private"))
	}
	joined = append(joined, goAway)
	_, ok = codeArtifactGoAway(errors.Join(joined...))
	assert.False(t, ok)
}

func TestCodeArtifactGoAwayLogPrivacyAndCancellation(t *testing.T) {
	debug := "https://private.example/token=secret\npayload\x00\"; LastStreamID=9000, ErrCode=CANCEL"
	for _, test := range []struct {
		name      string
		cancel    bool
		join      bool
		debugData string
	}{
		{name: "peer debug", debugData: debug},
		{name: "large peer debug", debugData: strings.Repeat(debug, 16384)},
		{name: "canceled request", cancel: true, debugData: debug},
		{name: "joined cancellation", join: true, debugData: debug},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			recorded := &recordingCodeArtifactMetrics{}
			strategy := &CodeArtifact{
				logger: slog.New(slog.NewJSONHandler(&logs, nil)),
				target: &url.URL{Scheme: "https", Host: "private.example"},
				metric: recorded,
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			spans := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
			t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
			ctx, span := provider.Tracer("goaway-test").Start(ctx, "download")
			if test.cancel {
				cancel()
			}
			var fault error = http2.GoAwayError{LastStreamID: 19999, ErrCode: http2.ErrCodeNo, DebugData: test.debugData}
			if test.join {
				fault = errors.Join(fault, context.Canceled)
			}
			fault = &url.Error{Op: "Get", URL: "https://private.example/?token=secret", Err: fault}
			request := httptest.NewRequest(http.MethodGet, "/pypi/private/simple/private/?token=secret", nil).WithContext(ctx)
			reader, writer := io.Pipe()
			t.Cleanup(func() { assert.NoError(t, reader.Close()) })
			assert.NoError(t, writer.CloseWithError(fault))
			assertCodeArtifactStreamAborted(t, func() { strategy.streamOriginBody(httptest.NewRecorder(), request, reader) })
			span.End()

			kind, status := "http2_goaway", codes.Error
			if test.cancel || test.join {
				kind, status = "client_canceled", codes.Unset
			}
			assert.Equal(t, [][3]string{{"source_read", kind, "pypi"}}, recorded.streamFailures)
			assert.Equal(t, status, spans.Ended()[0].Status().Code)
			var entry map[string]any
			assert.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
			assert.Equal[any](t, kind, entry["error_kind"])
			assert.Equal[any](t, test.cancel || test.join, entry["client_canceled"])
			assert.Equal[any](t, "NO_ERROR", entry["http2_error_code"])
			assert.Equal[any](t, float64(19999), entry["http2_last_stream_id"])
			for _, private := range []string{"private", "secret", "payload", "debug", "9000", "CANCEL"} {
				assert.False(t, strings.Contains(logs.String(), private))
			}
		})
	}
}

type codeArtifactDiagnosticWrapperError struct {
	message string
	inner   error
}

func (e codeArtifactDiagnosticWrapperError) Error() string { return e.message }
func (e codeArtifactDiagnosticWrapperError) Unwrap() error { return e.inner }

type codeArtifactDiagnosticCycleError struct {
	visits int
}

func (*codeArtifactDiagnosticCycleError) Error() string { panic("wrapper text must not be inspected") }
func (e *codeArtifactDiagnosticCycleError) Unwrap() error {
	e.visits++
	return e
}
