package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/strategy"
)

type readinessTestConfig struct{}

type readinessTestCache struct {
	cache.Cache
	ready *atomic.Bool
}

func (c *readinessTestCache) Ready() bool { return c.ready.Load() }

func readinessResponse(handler http.Handler, path string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	return response
}

func TestReadinessEndpointTracksLoadedCache(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	ready := &atomic.Bool{}
	ready.Store(true)
	cr := cache.NewRegistry()
	cache.Register(
		cr,
		"readiness-test",
		"Test cache with mutable readiness",
		func(context.Context, readinessTestConfig) (*readinessTestCache, error) {
			return &readinessTestCache{Cache: cache.NoOpCache(), ready: ready}, nil
		},
	)
	mr := metadatadb.NewRegistry()
	metadatadb.RegisterMemory(mr)
	sr := strategy.NewRegistry()
	strategy.RegisterAPIV1(sr)
	configAST, err := hcl.Parse(strings.NewReader(`
cache readiness-test {}
metadata memory {}
`))
	assert.NoError(t, err)
	var shuttingDown atomic.Bool
	handler, err := newMux(ctx, &shuttingDown, cr, mr, sr, configAST, nil)
	assert.NoError(t, err)

	response := readinessResponse(handler, "/_readiness")
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "OK", strings.TrimSpace(response.Body.String()))

	ready.Store(false)
	response = readinessResponse(handler, "/_readiness")
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Equal(t, "warming up", strings.TrimSpace(response.Body.String()))

	ready.Store(true)
	response = readinessResponse(handler, "/_readiness")
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "OK", strings.TrimSpace(response.Body.String()))
}
