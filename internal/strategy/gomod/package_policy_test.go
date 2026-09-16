package gomod //nolint:testpackage // White-box coverage is required for policy and cache injection.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/gitclone"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/packagepolicy"
)

type recordingPackagePolicy struct {
	decision      packagepolicy.Decision
	err           error
	purls         []string
	notApplicable int
}

type cacheProbe struct {
	cache.Cache
	createCalls int
}

func (c *cacheProbe) Create(
	ctx context.Context,
	key cache.Key,
	headers http.Header,
	ttl time.Duration,
	opts ...cache.Option,
) (cache.Writer, error) {
	c.createCalls++
	return c.Cache.Create(ctx, key, headers, ttl, opts...)
}

func (r *recordingPackagePolicy) Evaluate(_ context.Context, purl string) (packagepolicy.Decision, error) {
	r.purls = append(r.purls, purl)
	return r.decision, r.err
}

func (r *recordingPackagePolicy) ObserveNotApplicable(context.Context) {
	r.notApplicable++
}

func TestGoModuleHandlesPackagePolicyBeforeOrigin(t *testing.T) {
	tests := []struct {
		name           string
		decision       packagepolicy.Decision
		err            error
		statusCode     int
		policy         string
		originRequests int
		cacheWrites    int
	}{
		{
			name:       "denied package",
			decision:   packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Reasons: []string{"malware"}},
			statusCode: http.StatusForbidden,
			policy:     "deny",
		},
		{
			name:           "allowed package",
			decision:       packagepolicy.Decision{Verdict: packagepolicy.VerdictAllow},
			statusCode:     http.StatusOK,
			originRequests: 1,
			cacheWrites:    1,
		},
		{
			name:           "not applicable package",
			decision:       packagepolicy.Decision{Verdict: packagepolicy.VerdictNotApplicable},
			statusCode:     http.StatusOK,
			originRequests: 1,
			cacheWrites:    1,
		},
		{
			name:           "pending package",
			decision:       packagepolicy.Decision{Verdict: packagepolicy.VerdictPending},
			statusCode:     http.StatusOK,
			policy:         "pending",
			originRequests: 1,
		},
		{
			name:           "policy unavailable",
			err:            io.ErrUnexpectedEOF,
			statusCode:     http.StatusOK,
			policy:         "unavailable",
			originRequests: 1,
		},
		{
			name:       "fail-closed denial keeps the cause",
			decision:   packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Reasons: []string{"unavailable"}},
			err:        io.ErrUnexpectedEOF,
			statusCode: http.StatusForbidden,
			policy:     "deny",
		},
		{
			name: "local overload", err: packagepolicy.ErrOverloaded,
			statusCode: http.StatusServiceUnavailable, policy: "overloaded",
		},
		{
			name: "audit deny", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Audit: true},
			statusCode: http.StatusOK, policy: "audit-would_deny", originRequests: 1, cacheWrites: 1,
		},
		{
			name: "audit pending", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictPending, Audit: true},
			statusCode: http.StatusOK, policy: "audit-would_allow", originRequests: 1, cacheWrites: 1,
		},
		{
			name: "audit fail closed", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Audit: true}, err: io.ErrUnexpectedEOF,
			statusCode: http.StatusOK, policy: "audit-would_deny", originRequests: 1, cacheWrites: 1,
		},
		{
			name: "audit overload", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Audit: true}, err: packagepolicy.ErrOverloaded,
			statusCode: http.StatusOK, policy: "audit-would_deny", originRequests: 1, cacheWrites: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			var originRequests int
			policy := &recordingPackagePolicy{decision: test.decision, err: test.err}
			probe := &cacheProbe{Cache: cache.NoOpCache()}
			cacher := &goproxyCacher{cache: probe}
			cacheName := "github.com/pkg/errors/@v/v0.9.1.zip"
			strategy := &Strategy{
				packagePolicy: policy,
				logger:        slog.New(slog.NewJSONHandler(&logs, nil)),
				proxyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					originRequests++
					assert.NoError(t, cacher.Put(r.Context(), cacheName, strings.NewReader("module")))
					w.WriteHeader(http.StatusOK)
				}),
			}

			w := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/gomod/github.com/pkg/errors/@v/v0.9.1.zip", nil)
			strategy.serveHTTP(w, request)

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.policy, w.Header().Get("X-Cachew-Package-Policy"))
			assert.Equal(t, []string{"pkg:golang/github.com/pkg/errors@v0.9.1"}, policy.purls)
			assert.Equal(t, test.originRequests, originRequests)
			assert.Equal(t, test.cacheWrites, probe.createCalls)
			if test.err != nil {
				assert.Contains(t, logs.String(), test.err.Error())
			}
		})
	}
}

func TestGoModuleDeniedModuleNeverReachesProxy(t *testing.T) {
	policy := &recordingPackagePolicy{decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Reasons: []string{"malware"}}}
	strategy := &Strategy{
		packagePolicy: policy,
		proxyHandler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("denied module must not reach the proxy even when cached")
		}),
	}
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/gomod/github.com/pkg/errors/@v/v0.9.1.zip", nil)
	strategy.serveHTTP(w, request)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "deny", w.Header().Get("X-Cachew-Package-Policy"))
	assert.Equal(t, []string{"pkg:golang/github.com/pkg/errors@v0.9.1"}, policy.purls)
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
	request := httptest.NewRequest(http.MethodGet, "/gomod/github.com/myorg/private/submodule/@v/v1.0.0.zip", nil)
	strategy.serveHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "private module", w.Body.String())
	assert.Equal(t, []string(nil), policy.purls)
	assert.Equal(t, 1, policy.notApplicable)
}

func TestGoModuleBranchQueryBypassesPackagePolicy(t *testing.T) {
	policy := &recordingPackagePolicy{decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}}
	strategy := &Strategy{
		packagePolicy: policy,
		proxyHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "resolved branch")
		}),
	}
	w := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/gomod/github.com/pkg/errors/@v/master.info", nil)

	strategy.serveHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "resolved branch", w.Body.String())
	assert.Equal(t, []string(nil), policy.purls)
	assert.Equal(t, 1, policy.notApplicable)
}

func TestGoModuleHeadRequestDoesNotFetchOrCache(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "policy disabled", true: "policy enabled"}[enabled], func(t *testing.T) {
			var originRequests atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				originRequests.Add(1)
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(origin.Close)
			ctx := logging.ContextWithLogger(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			probe := &cacheProbe{Cache: cache.NoOpCache()}
			mux := http.NewServeMux()
			manager := gitclone.NewManagerProvider(ctx, gitclone.Config{MirrorRoot: t.TempDir()}, nil)
			strategy, err := New(ctx, Config{Proxy: origin.URL}, probe, mux, manager)
			assert.NoError(t, err)
			policy := &recordingPackagePolicy{decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}}
			if enabled {
				strategy.packagePolicy = policy
			}

			for _, extension := range []string{"info", "mod", "zip"} {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/gomod/github.com/pkg/errors/@v/v0.9.1."+extension, nil))
				assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
				assert.Equal(t, http.MethodGet, w.Header().Get("Allow"))
			}

			assert.Equal(t, int64(0), originRequests.Load())
			assert.Equal(t, 0, probe.createCalls)
			assert.Equal(t, []string(nil), policy.purls)
			assert.Equal(t, 0, policy.notApplicable)
		})
	}
}
