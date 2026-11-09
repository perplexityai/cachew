package handler_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy/handler"
)

type disconnectedResponseWriter struct {
	*httptest.ResponseRecorder
}

func (w disconnectedResponseWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestErrorLogsDoNotExposeSignedCacheURL(t *testing.T) {
	const requestURL = "https://downloads.example.invalid/object?X-Amz-Credential=synthetic-credential&X-Amz-Signature=synthetic-signature&X-Amz-Security-Token=synthetic-session-token"
	payload := strings.Repeat("cached download", 64<<10)

	for _, cacheHit := range []bool{false, true} {
		name := "CacheWriteFailure"
		if cacheHit {
			name = "CachedResponseFailure"
		}
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			ctx := logging.ContextWithLogger(t.Context(), logger)
			mem := mustNewMemoryCache(t)
			key := cache.NewKey(requestURL)
			var c cache.Cache = failingWriteCache{Cache: mem}
			recorder := httptest.NewRecorder()
			var response http.ResponseWriter = recorder
			wantError := "metadata too large"
			wantCacheResult := handler.CacheResultMiss

			if cacheHit {
				writer, err := mem.Create(ctx, key, http.Header{}, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(writer, payload); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				c = mem
				response = disconnectedResponseWriter{recorder}
				wantError = io.ErrClosedPipe.Error()
				wantCacheResult = handler.CacheResultHit
			}

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if cacheHit {
					t.Error("cache hit unexpectedly fetched upstream")
				}
				_, _ = io.WriteString(w, payload)
			}))
			t.Cleanup(backend.Close)
			h := handler.New(backend.Client(), c).
				Transform(func(r *http.Request) (*http.Request, error) {
					return http.NewRequestWithContext(r.Context(), http.MethodGet, backend.URL, nil)
				})
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx))

			var record struct {
				Level    string `json:"level"`
				CacheKey string `json:"cache_key"`
				Error    string `json:"error"`
			}
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
				t.Fatalf("expected one error log: %v", err)
			}
			if record.Level != "ERROR" || !strings.Contains(record.Error, wantError) {
				t.Fatal("injected failure was not observable at ERROR level")
			}
			for _, secret := range []string{"synthetic-credential", "synthetic-signature", "synthetic-session-token"} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("error log exposed synthetic signed-URL field %q", secret)
				}
			}
			if record.CacheKey != key.String() {
				t.Error("error log did not identify the opaque cache object key")
			}
			if recorder.Header().Get(handler.CacheResultHeader) != wantCacheResult {
				t.Fatal("request did not exercise the expected cache path")
			}
			if !cacheHit && (recorder.Code != http.StatusOK || recorder.Body.String() != payload) {
				t.Fatal("cache failure interrupted the successful upstream response")
			}
			if !cacheHit {
				reader, _, err := mem.Open(ctx, key)
				if reader != nil {
					_ = reader.Close()
				}
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed cache write left an entry: %v", err)
				}
			}
		})
	}
}
