package strategy //nolint:testpackage // Benchmark the real CodeArtifact handler with a fixed external credential source.

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
)

type benchmarkCodeArtifactTokens struct{}

func (benchmarkCodeArtifactTokens) Token(context.Context, uint64) (codeArtifactToken, error) {
	return codeArtifactToken{value: "benchmark", event: codeArtifactAuthReuse}, nil
}

func BenchmarkCodeArtifactFill(b *testing.B) {
	payload := strings.Repeat("artifact", 32768)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
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
			mux := http.NewServeMux()
			_, err := newCodeArtifact(ctx, testCodeArtifactConfig(origin.URL), mux, benchmarkCodeArtifactTokens{}, store, true)
			if err != nil {
				b.Fatal(err)
			}
			path := codeArtifactPath(origin, "/npm/repository/artifact/-/artifact-1.0.0.tgz")
			run := func() {
				requestCtx, cancel := context.WithCancel(ctx)
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(requestCtx))
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
