package handler_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/handler"
)

func BenchmarkCacheFill(b *testing.B) {
	payload := strings.Repeat("artifact", 32768)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = io.WriteString(w, payload)
	}))
	defer origin.Close()
	for _, name := range []string{"miss", "hit"} {
		b.Run(name, func(b *testing.B) {
			hit := name == "hit"
			ctx := logging.ContextWithLogger(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			store := cache.NoOpCache()
			if hit {
				memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 4, MaxTTL: time.Hour})
				if err != nil {
					b.Fatal(err)
				}
				defer memory.Close() //nolint:errcheck // Benchmark cleanup.
				store = memory
			}
			serve := handler.New(origin.Client(), store).Transform(func(r *http.Request) (*http.Request, error) {
				return http.NewRequestWithContext(r.Context(), http.MethodGet, origin.URL, nil)
			})
			run := func() {
				requestCtx, cancel := context.WithCancel(ctx)
				response := httptest.NewRecorder()
				serve.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/artifact", nil).WithContext(requestCtx))
				cancel()
				if response.Code != http.StatusOK || response.Body.Len() != len(payload) {
					b.Fatal("incomplete response")
				}
			}
			run()
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for b.Loop() {
				run()
			}
		})
	}
}
