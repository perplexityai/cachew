package strategy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/strategy"
)

const (
	githubObjectsTreeSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	githubObjectsToken   = "Bearer test-token"
)

type githubObjectsResponse struct {
	Objects []githubObjectResponse `json:"objects"`
}

type githubObjectResponse struct {
	Path string  `json:"path"`
	OID  *string `json:"oid"`
}

func TestGitHubObjectsCachesFoundAndMissingPathsIndependently(t *testing.T) {
	requests := make([]map[string]string, 0, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, githubObjectsToken, r.Header.Get("Authorization"))
		w.Header().Set("X-Ratelimit-Remaining", "4999")
		var body struct {
			Variables map[string]string `json:"variables"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		requests = append(requests, body.Variables)

		objects := make(map[string]any)
		for key, expression := range body.Variables {
			if key == "owner" || key == "repo" || key == "tree" {
				continue
			}
			if strings.HasSuffix(expression, ":missing/OWNERS.yaml") {
				objects["o"+strings.TrimPrefix(key, "expr")] = nil
				continue
			}
			objects["o"+strings.TrimPrefix(key, "expr")] = map[string]string{
				"__typename": "Blob",
				"oid":        strings.Repeat("b", 40),
			}
		}
		objects["root"] = map[string]string{
			"__typename": "Tree",
			"oid":        githubObjectsTreeSHA,
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"repository": objects},
		})
	}))
	t.Cleanup(upstream.Close)

	mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)
	first := postGitHubObjects(ctx, t, mux, []string{"a/OWNERS.yaml", "missing/OWNERS.yaml"})
	second := postGitHubObjects(ctx, t, mux, []string{"missing/OWNERS.yaml", "c/OWNERS.yaml"})

	assert.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, "4999", first.Header().Get("X-Ratelimit-Remaining"))
	assert.Equal(t, githubObjectsResponse{
		Objects: []githubObjectResponse{
			{Path: "a/OWNERS.yaml", OID: stringPointer(strings.Repeat("b", 40))},
			{Path: "missing/OWNERS.yaml"},
		},
	}, decodeGitHubObjectsResponse(t, first))
	assert.Equal(t, http.StatusOK, second.Code)
	secondResponse := decodeGitHubObjectsResponse(t, second)
	assert.Equal(t, githubObjectsResponse{
		Objects: []githubObjectResponse{
			{Path: "missing/OWNERS.yaml"},
			{Path: "c/OWNERS.yaml", OID: stringPointer(strings.Repeat("b", 40))},
		},
	}, secondResponse)
	assert.Equal(t, 2, len(requests))
	assert.Equal(t, 5, len(requests[0]))
	assert.Equal(t, 4, len(requests[1]), "only the uncached path should reach GitHub")
}

func TestGitHubObjectsRejectsInvalidImmutableLookup(t *testing.T) {
	mux, ctx := newGitHubObjectsTestMux(t, "https://api.github.invalid/graphql")
	tests := []struct {
		name string
		body string
	}{
		{name: "mutable revision", body: `{"tree_sha":"main","paths":["OWNERS.yaml"]}`},
		{name: "parent path", body: `{"tree_sha":"` + githubObjectsTreeSHA + `","paths":["../OWNERS.yaml"]}`},
		{name: "duplicate path", body: `{"tree_sha":"` + githubObjectsTreeSHA + `","paths":["OWNERS.yaml","OWNERS.yaml"]}`},
		{name: "unknown field", body: `{"tree_sha":"` + githubObjectsTreeSHA + `","paths":["OWNERS.yaml"],"extra":true}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api.github.com/repos/ppl-ai/agi/git/objects:batch", strings.NewReader(test.body))
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			assert.Equal(t, http.StatusBadRequest, response.Code)
		})
	}
}

func TestGitHubObjectsFailsClosedOnGraphQLErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("X-Ratelimit-Remaining", "0")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":   map[string]any{"repository": map[string]any{"0": nil}},
			"errors": []map[string]string{{"message": "upstream failed", "type": "RATE_LIMITED"}},
		})
	}))
	t.Cleanup(upstream.Close)
	mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)

	response := postGitHubObjects(ctx, t, mux, []string{"OWNERS.yaml"})

	assert.Equal(t, http.StatusTooManyRequests, response.Code)
	assert.Equal(t, "30", response.Header().Get("Retry-After"))
	assert.Equal(t, "0", response.Header().Get("X-Ratelimit-Remaining"))
}

func TestGitHubObjectsDoesNotCacheMissingPathsUntilRootExists(t *testing.T) {
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		root := any(nil)
		object := any(nil)
		if requestCount == 2 {
			root = map[string]string{"__typename": "Tree", "oid": githubObjectsTreeSHA}
			object = map[string]string{"__typename": "Blob", "oid": strings.Repeat("b", 40)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"repository": map[string]any{"root": root, "o0": object}},
		})
	}))
	t.Cleanup(upstream.Close)
	mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)

	first := postGitHubObjects(ctx, t, mux, []string{"OWNERS.yaml"})
	second := postGitHubObjects(ctx, t, mux, []string{"OWNERS.yaml"})

	assert.Equal(t, http.StatusBadGateway, first.Code)
	assert.Equal(t, http.StatusOK, second.Code)
	assert.Equal(t, stringPointer(strings.Repeat("b", 40)), decodeGitHubObjectsResponse(t, second).Objects[0].OID)
	assert.Equal(t, 2, requestCount)
}

func TestGitHubObjectsDoesNotCacheMalformedObjectsAsMissing(t *testing.T) {
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		object := any(map[string]string{})
		if requestCount == 2 {
			object = map[string]string{"__typename": "Blob", "oid": strings.Repeat("b", 40)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"repository": map[string]any{
				"root": map[string]string{"__typename": "Tree", "oid": githubObjectsTreeSHA},
				"o0":   object,
			}},
		})
	}))
	t.Cleanup(upstream.Close)
	mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)

	first := postGitHubObjects(ctx, t, mux, []string{"OWNERS.yaml"})
	second := postGitHubObjects(ctx, t, mux, []string{"OWNERS.yaml"})

	assert.Equal(t, http.StatusBadGateway, first.Code)
	assert.Equal(t, http.StatusOK, second.Code)
	assert.Equal(t, 2, requestCount)
}

func TestGitHubObjectsPreservesRateLimitHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("X-Ratelimit-Remaining", "0")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(upstream.Close)
	mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)

	response := postGitHubObjects(ctx, t, mux, []string{"OWNERS.yaml"})

	assert.Equal(t, http.StatusTooManyRequests, response.Code)
	assert.Equal(t, "30", response.Header().Get("Retry-After"))
	assert.Equal(t, "0", response.Header().Get("X-Ratelimit-Remaining"))
}

func TestGitHubObjectsPreservesStrongestRateLimitAcrossBatchFailures(t *testing.T) {
	tests := []struct {
		name       string
		largeCode  int
		largeRetry string
		smallCode  int
		smallRetry string
	}{
		{
			name:       "rate limit wins over an earlier gateway failure",
			largeCode:  http.StatusBadGateway,
			smallCode:  http.StatusTooManyRequests,
			smallRetry: "60",
		},
		{
			name:       "longest cooldown wins across rate limits",
			largeCode:  http.StatusTooManyRequests,
			largeRetry: "30",
			smallCode:  http.StatusTooManyRequests,
			smallRetry: "60",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Variables map[string]string `json:"variables"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				code, retryAfter := test.largeCode, test.largeRetry
				if len(body.Variables)-3 == 1 {
					code, retryAfter = test.smallCode, test.smallRetry
					time.Sleep(20 * time.Millisecond)
				}
				if retryAfter != "" {
					w.Header().Set("Retry-After", retryAfter)
					w.Header().Set("X-Ratelimit-Remaining", "0")
				}
				http.Error(w, http.StatusText(code), code)
			}))
			t.Cleanup(upstream.Close)
			mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)
			paths := make([]string, 201)
			for index := range paths {
				paths[index] = fmt.Sprintf("dir-%d/OWNERS.yaml", index)
			}

			response := postGitHubObjects(ctx, t, mux, paths)

			assert.Equal(t, http.StatusTooManyRequests, response.Code)
			assert.Equal(t, "60", response.Header().Get("Retry-After"))
			assert.Equal(t, "0", response.Header().Get("X-Ratelimit-Remaining"))
		})
	}
}

func TestGitHubObjectsBoundsGraphQLBatchSize(t *testing.T) {
	requestSizes := make([]int, 0, 2)
	var requestsMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Variables map[string]string `json:"variables"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		requestsMu.Lock()
		requestSizes = append(requestSizes, len(body.Variables)-3)
		requestsMu.Unlock()
		objects := make(map[string]any, len(body.Variables)-2)
		for key := range body.Variables {
			if suffix, found := strings.CutPrefix(key, "expr"); found {
				objects["o"+suffix] = nil
			}
		}
		objects["root"] = map[string]string{"__typename": "Tree", "oid": githubObjectsTreeSHA}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": objects}})
	}))
	t.Cleanup(upstream.Close)
	mux, ctx := newGitHubObjectsTestMux(t, upstream.URL)
	paths := make([]string, 201)
	for index := range paths {
		paths[index] = fmt.Sprintf("dir-%d/OWNERS.yaml", index)
	}

	response := postGitHubObjects(ctx, t, mux, paths)

	assert.Equal(t, http.StatusOK, response.Code)
	slices.Sort(requestSizes)
	assert.Equal(t, []int{1, 200}, requestSizes)
}

func newGitHubObjectsTestMux(t *testing.T, target string) (*http.ServeMux, context.Context) {
	t.Helper()
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	mux := http.NewServeMux()
	_, err = strategy.NewGitHubObjects(ctx, strategy.GitHubObjectsConfig{Target: target}, memory, mux)
	assert.NoError(t, err)
	return mux, ctx
}

func postGitHubObjects(ctx context.Context, t *testing.T, mux http.Handler, paths []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"tree_sha": githubObjectsTreeSHA, "paths": paths})
	assert.NoError(t, err)
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api.github.com/repos/ppl-ai/agi/git/objects:batch", strings.NewReader(string(body)))
	request.Header.Set("Authorization", githubObjectsToken)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func decodeGitHubObjectsResponse(t *testing.T, response *httptest.ResponseRecorder) githubObjectsResponse {
	t.Helper()
	var decoded githubObjectsResponse
	assert.NoError(t, json.NewDecoder(response.Body).Decode(&decoded))
	return decoded
}

func stringPointer(value string) *string { return &value }
