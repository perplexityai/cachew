package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/admission"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metrics"
	"github.com/block/cachew/internal/opa"
)

const serverAdmissionTestTimeout = 2 * time.Second

func startServerAdmissionRequest(ctx context.Context, handler http.Handler, path string) <-chan *httptest.ResponseRecorder {
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		handler.ServeHTTP(response, request)
		result <- response
	}()
	return result
}

func waitForServerAdmission(t *testing.T, entered <-chan string) string {
	t.Helper()
	select {
	case path := <-entered:
		return path
	case <-time.After(serverAdmissionTestTimeout):
		t.Fatal("request did not reach the cache handler")
		return ""
	}
}

func waitForServerAdmissionResponse(t *testing.T, response <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case result := <-response:
		return result
	case <-time.After(serverAdmissionTestTimeout):
		t.Fatal("request did not complete")
		return nil
	}
}

func TestLoadGlobalConfigRequestAdmission(t *testing.T) {
	ast, err := hcl.Parse(strings.NewReader(`
request-admission {
  limit = 512
  reserved = 8
}
log {
  level = "info"
}
`))
	assert.NoError(t, err)
	config, _, err := loadGlobalConfig(ast)
	assert.NoError(t, err)
	assert.Equal(t, 512, config.RequestAdmission.Limit)
	assert.Equal(t, 8, config.RequestAdmission.Reserved)
}

func TestServerWiresAuthorizationBeforeRequestAdmission(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	entered := make(chan string, 2)
	release := make(chan struct{})
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.URL.Path
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	server, err := newServer(
		ctx,
		downstream,
		"127.0.0.1:0",
		metrics.Config{ServiceName: "cachew-test"},
		opa.Config{},
		logging.Config{Level: slog.LevelError},
		admission.Config{Limit: 2, Reserved: 1},
	)
	assert.NoError(t, err)

	normal := startServerAdmissionRequest(ctx, server.Handler, "/artifact/held")
	assert.Equal(t, "/artifact/held", waitForServerAdmission(t, entered))

	rejected := httptest.NewRecorder()
	server.Handler.ServeHTTP(rejected, httptest.NewRequest(http.MethodGet, "/artifact/rejected", nil).WithContext(ctx))
	assert.Equal(t, http.StatusServiceUnavailable, rejected.Code)
	assert.Equal(t, "1", rejected.Header().Get("Retry-After"))

	readiness := startServerAdmissionRequest(ctx, server.Handler, "/_readiness")
	assert.Equal(t, "/_readiness", waitForServerAdmission(t, entered))

	denied := httptest.NewRecorder()
	server.Handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/admin/pprof/heap", nil).WithContext(ctx))
	assert.Equal(t, http.StatusForbidden, denied.Code)

	close(release)
	assert.Equal(t, http.StatusNoContent, waitForServerAdmissionResponse(t, normal).Code)
	assert.Equal(t, http.StatusNoContent, waitForServerAdmissionResponse(t, readiness).Code)

	afterDrain := httptest.NewRecorder()
	server.Handler.ServeHTTP(afterDrain, httptest.NewRequest(http.MethodGet, "/artifact/after-drain", nil).WithContext(ctx))
	assert.Equal(t, http.StatusNoContent, afterDrain.Code)
}
