package strategy //nolint:testpackage // Exercise the real proxy with a failing HTTP origin.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

func TestCodeArtifactAbortsTruncatedResponse(t *testing.T) {
	for _, mode := range []string{"passthrough", "uncacheable", "cache_fill"} {
		for _, protocol := range []string{"http1", "http2"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				partial := `{"files":[{"filename":"` + strings.Repeat("x", 64<<10)
				mux, origin, _, strategy, _ := newTestCachingCodeArtifact(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
					if mode == "cache_fill" {
						w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
					}
					_, _ = io.WriteString(w, partial)
					assert.NoError(t, http.NewResponseController(w).Flush())
					panic(http.ErrAbortHandler)
				}))
				var logs bytes.Buffer
				strategy.logger = slog.New(slog.NewJSONHandler(&logs, nil))
				recorded := &recordingCodeArtifactMetrics{}
				strategy.metric = recorded
				finished := make(chan struct{})
				proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(finished)
					mux.ServeHTTP(w, r)
				}))
				proxy.EnableHTTP2 = protocol == "http2"
				proxy.StartTLS()
				t.Cleanup(proxy.Close)
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
					proxy.URL+codeArtifactPath(origin, "/pypi/repository/simple/grpcio/"), nil)
				assert.NoError(t, err)
				if mode == "passthrough" {
					request.Header.Set("Cache-Control", "no-cache")
				}
				response, err := proxy.Client().Do(request)
				assert.NoError(t, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err == nil {
					t.Fatalf("truncated JSON accepted as complete HTTP response: status=%d bytes=%d", response.StatusCode, len(body))
				}
				<-finished
				assert.Equal(t, protocol == "http2", response.ProtoMajor == 2)
				assert.Equal(t, []recordedCodeArtifactOrigin{{status: "unexpected_eof", format: "pypi", size: int64(len(partial))}}, recorded.origin)
				var entry map[string]any
				assert.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
				assert.Equal[any](t, "source_read", entry["stage"])
				assert.Equal[any](t, "unexpected_eof", entry["error_kind"])
				assert.Equal[any](t, float64(len(partial)), entry["bytes_read"])
				assert.Equal[any](t, float64(len(partial)), entry["bytes_written"])
				assert.Equal[any](t, float64(-1), entry["expected_bytes"])
			})
		}
	}
}

func assertCodeArtifactStreamAborted(t *testing.T, fn func()) {
	t.Helper()
	defer func() { assert.Equal[any](t, http.ErrAbortHandler, recover()) }()
	fn()
}

type failedCodeArtifactWriter struct {
	http.ResponseWriter
	err error
}

func (w failedCodeArtifactWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCodeArtifactStreamFailureDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name        string
		fault       error
		clientWrite bool
		cancel      bool
		kind        string
	}{
		{name: "origin idle timeout", fault: errCodeArtifactOriginReadIdleTimeout, kind: "read_idle_timeout"},
		{name: "client cancellation", fault: context.Canceled, cancel: true, kind: "canceled"},
		{name: "client write", fault: syscall.EPIPE, clientWrite: true, kind: "broken_pipe"},
		{name: "origin reset", fault: syscall.ECONNRESET, kind: "connection_reset"},
		{name: "private error", fault: errors.New("secret-url?token=private"), kind: "transport_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			strategy := &CodeArtifact{logger: slog.New(slog.NewJSONHandler(&logs, nil)), target: &url.URL{Scheme: "https", Host: "origin.example"}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				cancel()
			}
			request := httptest.NewRequest(http.MethodGet, "/pypi/private/simple/package/?token=private", nil).WithContext(ctx)
			var w http.ResponseWriter = httptest.NewRecorder()
			w.Header().Set("Content-Length", "100")
			reader, writer := io.Pipe()
			assert.NoError(t, writer.CloseWithError(test.fault))
			var body io.Reader = reader
			stage := "source_read"
			if test.clientWrite {
				body = strings.NewReader("payload")
				w = failedCodeArtifactWriter{ResponseWriter: w, err: test.fault}
				stage = "client_write"
			}
			assertCodeArtifactStreamAborted(t, func() { strategy.streamOriginBody(w, request, body) })
			assert.NoError(t, reader.Close())
			var entry map[string]any
			assert.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
			assert.Equal[any](t, stage, entry["stage"])
			assert.Equal[any](t, test.kind, entry["error_kind"])
			assert.Equal[any](t, test.cancel, entry["client_canceled"])
			assert.Equal[any](t, float64(100), entry["expected_bytes"])
			assert.False(t, strings.Contains(logs.String(), "private"))
		})
	}
}
