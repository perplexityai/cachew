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
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/block/cachew/internal/cache"
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
				spans := tracetest.NewSpanRecorder()
				provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
				t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
				handler := otelhttp.NewHandler(mux, "codeartifact", otelhttp.WithTracerProvider(provider))
				finished := make(chan struct{})
				proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(finished)
					handler.ServeHTTP(w, r)
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
				assert.Equal(t, [][3]string{{"source_read", "unexpected_eof", "pypi"}}, recorded.streamFailures)
				ended := spans.Ended()
				assert.Equal(t, 1, len(ended))
				assert.Equal(t, codes.Error, ended[0].Status().Code)
				assert.Equal(t, "unexpected_eof", ended[0].Status().Description)
				entries := codeArtifactFailureLogs(t, logs.Bytes())
				entry := entries[len(entries)-1]
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
		{name: "client cancellation", fault: context.Canceled, cancel: true, kind: "client_canceled"},
		{name: "client write", fault: syscall.EPIPE, clientWrite: true, kind: "broken_pipe"},
		{name: "origin reset", fault: syscall.ECONNRESET, kind: "connection_reset"},
		{name: "private error", fault: errors.New("secret-url?token=private"), kind: "transport_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			recorded := &recordingCodeArtifactMetrics{}
			strategy := &CodeArtifact{logger: slog.New(slog.NewJSONHandler(&logs, nil)), target: &url.URL{Scheme: "https", Host: "origin.example"}, metric: recorded}
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
			assert.Equal(t, [][3]string{{stage, test.kind, "pypi"}}, recorded.streamFailures)
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

func codeArtifactFailureLogs(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var entries []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var entry map[string]any
		err := decoder.Decode(&entry)
		if errors.Is(err, io.EOF) {
			break
		}
		assert.NoError(t, err)
		entries = append(entries, entry)
	}
	return entries
}

type failingCodeArtifactCache struct {
	cache.Cache
	writer cache.Writer
}

func (c failingCodeArtifactCache) Create(context.Context, cache.Key, http.Header, time.Duration, ...cache.Option) (cache.Writer, error) {
	return c.writer, nil
}

type failedCodeArtifactCacheWriter struct {
	cache.Writer
	aborted bool
}

func (w *failedCodeArtifactCacheWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

func (w *failedCodeArtifactCacheWriter) Abort(error) error {
	w.aborted = true
	return syscall.ECONNRESET
}

func TestCodeArtifactLogsCacheFailuresBeforeAbortingStream(t *testing.T) {
	var logs bytes.Buffer
	writer := &failedCodeArtifactCacheWriter{}
	strategy := &CodeArtifact{
		logger: slog.New(slog.NewJSONHandler(&logs, nil)), target: &url.URL{Scheme: "https", Host: "origin.example"},
		cache: failingCodeArtifactCache{Cache: cache.NoOpCache(), writer: writer}, metric: &recordingCodeArtifactMetrics{},
	}
	failure, producer := io.Pipe()
	assert.NoError(t, producer.CloseWithError(io.ErrUnexpectedEOF))
	defer failure.Close()
	body := io.MultiReader(strings.NewReader("payload"), failure)
	headers := http.Header{"Cache-Control": {testCodeArtifactCacheControl}}
	response := &http.Response{Body: io.NopCloser(body)}
	request := httptest.NewRequest(http.MethodGet, "/pypi/private/package.whl", nil)
	assertCodeArtifactStreamAborted(t, func() {
		strategy.streamAndCache(httptest.NewRecorder(), request, response, headers)
	})
	assert.True(t, writer.aborted)
	entries := codeArtifactFailureLogs(t, logs.Bytes())
	assert.Equal(t, 2, len(entries))
	assert.Equal[any](t, "broken_pipe", entries[0]["write_error_kind"])
	assert.Equal[any](t, "connection_reset", entries[0]["abort_error_kind"])
	assert.Equal[any](t, "unexpected_eof", entries[1]["error_kind"])
}
