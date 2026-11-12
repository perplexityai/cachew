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
			// The client is still served in full, so a failed cache write is a warning.
			wantLevel := "WARN"
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
				wantLevel = "ERROR"
				wantCacheResult = handler.CacheResultHit
			}

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if cacheHit {
					t.Error("cache hit unexpectedly fetched upstream")
				}
				_, _ = io.WriteString(w, payload)
			}))
			t.Cleanup(backend.Close)
			h := handler.New(backend.Client(), c, newTestSpools(t)).
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
			if record.Level != wantLevel || !strings.Contains(record.Error, wantError) {
				t.Fatalf("injected failure was not logged at %s level", wantLevel)
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

func TestFetchFailureDoesNotExposeSignedURLs(t *testing.T) {
	const query = "?X-Amz-Credential=synthetic-credential&X-Amz-Signature=synthetic-signature"
	// A closed listener makes the client fail with an error that quotes the URL.
	origin := httptest.NewServer(http.NotFoundHandler())
	originURL := origin.URL
	origin.Close()

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			ctx := logging.ContextWithLogger(t.Context(), logger)
			h := handler.New(http.DefaultClient, mustNewMemoryCache(t), newTestSpools(t)).
				Transform(func(r *http.Request) (*http.Request, error) {
					return http.NewRequestWithContext(r.Context(), http.MethodGet, originURL+"/object"+query, nil)
				})
			recorder := httptest.NewRecorder()
			h.ServeHTTP(recorder, httptest.NewRequest(method, "/downloads.example.invalid/object"+query, nil).WithContext(ctx))

			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("got status %d, want %d", recorder.Code, http.StatusBadGateway)
			}
			var record struct {
				Level   string `json:"level"`
				Message string `json:"msg"`
				URL     string `json:"url"`
			}
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
				t.Fatalf("expected one error log: %v", err)
			}
			if record.Level != "ERROR" || !strings.Contains(record.Message, originURL+"/object?REDACTED") {
				t.Errorf("fetch failure was not logged with its redacted origin URL: %s", logs.String())
			}
			if record.URL != "/downloads.example.invalid/object?REDACTED" {
				t.Errorf("fetch failure was not logged with its redacted request URL: %q", record.URL)
			}
			for _, output := range []string{logs.String(), recorder.Body.String()} {
				if strings.Contains(output, "synthetic") || strings.Contains(output, "X-Amz") {
					t.Errorf("fetch failure exposed a signed-URL query: %s", output)
				}
			}
		})
	}
}
