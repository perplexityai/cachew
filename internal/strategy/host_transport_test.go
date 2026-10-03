package strategy //nolint:testpackage // TLS tests need to trust the test server on the private transport.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
)

func TestHostOriginRecovery(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			var protocol atomic.Int32
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protocol.Store(int32(r.ProtoMajor))
				if calls.Add(1) == 1 {
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte("recovered"))
			}))
			backend.EnableHTTP2 = h2
			backend.StartTLS()
			defer backend.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, ctx = logging.Configure(ctx, logging.Config{Level: slog.LevelError})
			memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
			assert.NoError(t, err)
			defer memCache.Close()
			mux := http.NewServeMux()
			host, err := NewHost(ctx, HostConfig{
				Target:               backend.URL,
				OriginHeaderTimeout:  100 * time.Millisecond,
				HTTP2ReadIdleTimeout: 50 * time.Millisecond,
				HTTP2PingTimeout:     50 * time.Millisecond,
			}, memCache, mux)
			assert.NoError(t, err)
			transport := host.client.Transport.(*http.Transport)
			transport.TLSClientConfig = backend.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			defer transport.CloseIdleConnections()
			u, err := url.Parse(backend.URL)
			assert.NoError(t, err)
			path := "/" + u.Host + "/same-object"
			for _, want := range []int{http.StatusBadGateway, http.StatusOK, http.StatusOK} {
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil))
				assert.Equal(t, want, response.Code)
				if want == http.StatusOK {
					assert.Equal(t, "recovered", response.Body.String())
				}
			}
			assert.NoError(t, ctx.Err())
			assert.Equal(t, int32(2), calls.Load(), "failed responses must not be cached; recovered responses must be")
			wantProtocol := int32(1)
			if h2 {
				wantProtocol = 2
			}
			assert.Equal(t, wantProtocol, protocol.Load())
		})
	}
}

func TestHostHeaderTimeoutDoesNotLimitBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(150 * time.Millisecond):
			_, _ = w.Write([]byte("complete artifact"))
		case <-r.Context().Done():
		}
	}))
	defer backend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, ctx = logging.Configure(ctx, logging.Config{Level: slog.LevelError})
	memCache, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer memCache.Close()
	mux := http.NewServeMux()
	host, err := NewHost(ctx, HostConfig{Target: backend.URL, OriginHeaderTimeout: 50 * time.Millisecond}, memCache, mux)
	assert.NoError(t, err)
	defer host.client.CloseIdleConnections()
	u, err := url.Parse(backend.URL)
	assert.NoError(t, err)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/"+u.Host+"/artifact", nil))
	assert.NoError(t, ctx.Err())
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "complete artifact", response.Body.String())
}
