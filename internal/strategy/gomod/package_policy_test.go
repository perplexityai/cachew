package gomod //nolint:testpackage // White-box coverage is required for policy and cache injection.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/packagepolicy"
)

type recordingPackagePolicy struct {
	decision packagepolicy.Decision
	err      error
	purls    []string
}

func (r *recordingPackagePolicy) Evaluate(_ context.Context, purl string) (packagepolicy.Decision, error) {
	r.purls = append(r.purls, purl)
	return r.decision, r.err
}

func TestGoModuleEnforcesPackagePolicyBeforeOrigin(t *testing.T) {
	tests := []struct {
		name       string
		decision   packagepolicy.Decision
		err        error
		statusCode int
		policy     string
	}{
		{
			name:       "denied package",
			decision:   packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Reasons: []string{"malware"}},
			statusCode: http.StatusForbidden,
			policy:     "deny",
		},
		{
			name:       "pending package",
			decision:   packagepolicy.Decision{Verdict: packagepolicy.VerdictPending},
			statusCode: http.StatusServiceUnavailable,
			policy:     "pending",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var originRequests int
			policy := &recordingPackagePolicy{decision: test.decision, err: test.err}
			strategy := &Strategy{
				packagePolicy: policy,
				proxyHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					originRequests++
					w.WriteHeader(http.StatusOK)
				}),
			}

			w := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/gomod/github.com/pkg/errors/@v/v0.9.1.zip", nil)
			strategy.serveHTTP(w, request)

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.policy, w.Header().Get("X-Cachew-Package-Policy"))
			assert.Equal(t, []string{"pkg:golang/github.com/pkg/errors@v0.9.1"}, policy.purls)
			assert.Equal(t, 0, originRequests)
		})
	}
}

func TestGoModuleCachedPackageBypassesPackagePolicy(t *testing.T) {
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	cacher := &goproxyCacher{cache: memory}
	cacheName := "github.com/pkg/errors/@v/v0.9.1.zip"
	assert.NoError(t, cacher.Put(ctx, cacheName, strings.NewReader("cached module")))

	policy := &recordingPackagePolicy{decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}}
	strategy := &Strategy{
		packagePolicy: policy,
		cacher:        cacher,
		proxyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "true", r.Header.Get("Disable-Module-Fetch"))
			_, _ = io.WriteString(w, "cached module")
		}),
	}
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/gomod/"+cacheName, nil)
	strategy.serveHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "cached module", w.Body.String())
	assert.Equal(t, []string(nil), policy.purls)
}

func TestGoModulePrivatePackageBypassesPackagePolicy(t *testing.T) {
	policy := &recordingPackagePolicy{decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}}
	strategy := &Strategy{
		config:        Config{PrivatePaths: []string{"github.com/myorg/*"}},
		packagePolicy: policy,
		proxyHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "private module")
		}),
	}
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/gomod/github.com/myorg/private/@v/v1.0.0.zip", nil)
	strategy.serveHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "private module", w.Body.String())
	assert.Equal(t, []string(nil), policy.purls)
}
