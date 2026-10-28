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
		noMetrics   bool
		kind        string
	}{
		{name: "origin idle timeout", fault: errCodeArtifactOriginReadIdleTimeout, kind: "read_idle_timeout"},
		{name: "client cancellation", fault: context.Canceled, cancel: true, kind: "client_canceled"},
		{name: "client write", fault: syscall.EPIPE, clientWrite: true, kind: "broken_pipe"},
		{name: "origin reset", fault: syscall.ECONNRESET, kind: "connection_reset"},
		{name: "private error", fault: errors.New("secret-url?token=private"), kind: "transport_error"},
		{name: "missing metrics", fault: io.ErrUnexpectedEOF, noMetrics: true, kind: "unexpected_eof"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			recorded := &recordingCodeArtifactMetrics{}
			strategy := &CodeArtifact{logger: slog.New(slog.NewJSONHandler(&logs, nil)), target: &url.URL{Scheme: "https", Host: "origin.example"}, metric: recorded}
			if test.noMetrics {
				strategy.metric = nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			spans := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
			t.Cleanup(func() { assert.NoError(t, provider.Shutdown(context.Background())) })
			ctx, span := provider.Tracer("stream-test").Start(ctx, "download")
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
			span.End()
			wantStatus := codes.Error
			if test.cancel {
				wantStatus = codes.Unset
			}
			assert.Equal(t, wantStatus, spans.Ended()[0].Status().Code)
			if !test.noMetrics {
				assert.Equal(t, [][3]string{{stage, test.kind, "pypi"}}, recorded.streamFailures)
			}
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
	aborted  bool
	writeErr error
	abortErr error
}

func (w *failedCodeArtifactCacheWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return len(p), nil
}

func (w *failedCodeArtifactCacheWriter) Abort(cause error) error {
	w.aborted = true
	return errors.Join(cause, w.abortErr)
}

func TestCodeArtifactLogsCacheFailureDetails(t *testing.T) {
	for _, test := range []struct {
		name        string
		writeErr    error
		abortErr    error
		streamFails bool
	}{
		{name: "full disk with successful download", writeErr: syscall.ENOSPC},
		{name: "AccessDenied error text with successful download", writeErr: errors.New("S3 AccessDenied: write denied")},
		{name: "SlowDown error text with successful download", writeErr: errors.New("S3 SlowDown: reduce request rate")},
		{name: "combined failures", writeErr: syscall.ENOSPC, abortErr: errors.New("storage cleanup failed"), streamFails: true},
		{name: "abort echoes private origin error", abortErr: errors.New("storage cleanup failed"), streamFails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			writer := &failedCodeArtifactCacheWriter{writeErr: test.writeErr, abortErr: test.abortErr}
			strategy := &CodeArtifact{
				logger: slog.New(slog.NewJSONHandler(&logs, nil)), target: &url.URL{Scheme: "https", Host: "origin.example"},
				cache: failingCodeArtifactCache{Cache: cache.NoOpCache(), writer: writer}, metric: &recordingCodeArtifactMetrics{},
			}
			failure, producer := io.Pipe()
			assert.NoError(t, producer.CloseWithError(errors.New("private-origin?token=secret")))
			defer failure.Close()
			var body io.Reader = strings.NewReader("payload")
			if test.streamFails {
				body = io.MultiReader(body, failure)
			}
			headers := http.Header{"Cache-Control": {testCodeArtifactCacheControl}}
			response := &http.Response{Body: io.NopCloser(body)}
			request := httptest.NewRequest(http.MethodGet, "/pypi/private/package.whl", nil)
			w := httptest.NewRecorder()
			run := func() { strategy.streamAndCache(w, request, response, headers) }
			if test.streamFails {
				assertCodeArtifactStreamAborted(t, run)
			} else {
				run()
			}
			assert.Equal(t, "payload", w.Body.String())
			assert.True(t, writer.aborted)
			entries := codeArtifactFailureLogs(t, logs.Bytes())
			wantLogs := 1
			if test.streamFails {
				wantLogs = 2
				assert.Equal[any](t, "transport_error", entries[1]["error_kind"])
			}
			assert.Equal(t, wantLogs, len(entries))
			cacheError, ok := entries[0]["error"].(string)
			assert.True(t, ok)
			for _, err := range []error{test.writeErr, test.abortErr} {
				if err != nil {
					assert.Contains(t, cacheError, err.Error())
				}
			}
			assert.False(t, strings.Contains(logs.String(), "private-origin"))
			assert.False(t, strings.Contains(logs.String(), "token=secret"))
		})
	}
}
