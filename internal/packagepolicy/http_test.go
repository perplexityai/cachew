package packagepolicy_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/packagepolicy"
)

func TestLogLevelKeepsNonProviderFaultsBelowError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		level slog.Level
	}{
		{name: "breaker skip", err: packagepolicy.ErrCircuitOpen, level: slog.LevelWarn},
		{name: "local overload", err: packagepolicy.ErrOverloaded, level: slog.LevelWarn},
		{name: "encoded separator", err: errors.Wrap(packagepolicy.ErrEncodedSeparator, "evaluate package policy"), level: slog.LevelWarn},
		{name: "unmappable package", err: errors.Wrap(packagepolicy.ErrUnmappablePackage, "evaluate package policy"), level: slog.LevelWarn},
		{name: "caller cancelled", err: errors.Wrap(context.Canceled, "socket policy: wait for shared evaluation"), level: slog.LevelDebug},
		{name: "provider failure", err: errors.New("socket policy: API returned 500"), level: slog.LevelError},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.level, packagepolicy.LogLevel(test.err))
		})
	}
}

func TestOverloadResponseAsksClientToRetry(t *testing.T) {
	w := httptest.NewRecorder()

	assert.False(t, packagepolicy.AllowRequest(w, packagepolicy.Decision{}, packagepolicy.ErrOverloaded))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "overloaded", w.Header().Get("X-Cachew-Package-Policy"))
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestAuditLeavesExcludedPackagesUnlabelled(t *testing.T) {
	w := httptest.NewRecorder()
	decision := packagepolicy.Decision{Verdict: packagepolicy.VerdictNotApplicable, Audit: true}

	assert.True(t, packagepolicy.AllowRequest(w, decision, nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", w.Header().Get("X-Cachew-Package-Policy"))
}

func TestAuditAndEnforcementResponses(t *testing.T) {
	tests := []struct {
		name      string
		decision  packagepolicy.Decision
		err       error
		status    int
		cacheable bool
	}{
		{name: "allow", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictAllow}, status: http.StatusOK, cacheable: true},
		{name: "deny", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, status: http.StatusForbidden},
		{name: "pending", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictPending}, status: http.StatusOK},
		{name: "unavailable", err: packagepolicy.ErrCircuitOpen, status: http.StatusOK},
		{name: "fail closed", decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, err: packagepolicy.ErrCircuitOpen, status: http.StatusForbidden},
		{name: "overload", err: packagepolicy.ErrOverloaded, status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			assert.Equal(t, test.status == http.StatusOK, packagepolicy.AllowRequest(w, test.decision, test.err))
			assert.Equal(t, test.status, w.Code)
			assert.Equal(t, test.cacheable, packagepolicy.Cacheable(test.decision, test.err))
			test.decision.Audit = true
			w = httptest.NewRecorder()
			assert.True(t, packagepolicy.AllowRequest(w, test.decision, test.err))
			assert.Equal(t, http.StatusOK, w.Code)
			assert.True(t, packagepolicy.Cacheable(test.decision, test.err))
			header := "audit-would_allow"
			if test.status != http.StatusOK {
				header = "audit-would_deny"
			}
			assert.Equal(t, header, w.Header().Get("X-Cachew-Package-Policy"))
			assert.Equal(t, "", w.Header().Get("Cache-Control"))
		})
	}
}
