package strategy //nolint:testpackage // Exercises the real HTTP path with a local origin and audit files.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/packageaudit"
	"github.com/block/cachew/internal/packagepolicy"
)

func TestCodeArtifactAuditRecordsEveryArtifactRequest(t *testing.T) {
	const packagePath = "/npm/repository/package/-/package-1.0.0.tgz"
	const privatePath = "/npm/repository/@private/name/-/name-1.0.0.tgz"
	const purl = "pkg:npm/package@1.0.0"
	mux, origin, _, strategy, ctx := newTestCachingCodeArtifact(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, testCodeArtifactBody)
	}))
	directory := filepath.Join(t.TempDir(), "audit")
	sink, err := packageaudit.New(packageaudit.Config{Directory: directory}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sink.Close(context.Background())) })
	strategy.packageAudit = sink
	policy := &recordingPackagePolicy{}
	strategy.packagePolicy = policy
	tests := []struct {
		path, method, verdict, policyError, action, source string
		decision                                           packagepolicy.Decision
		err                                                error
		status                                             int
		redacted                                           bool
	}{
		{packagePath, http.MethodGet, "allow", "", "allow", "origin", packagepolicy.Decision{Verdict: packagepolicy.VerdictAllow}, nil, 200, false},
		{packagePath, http.MethodGet, "allow", "", "allow", "cache", packagepolicy.Decision{Verdict: packagepolicy.VerdictAllow, VerdictCacheHit: true}, nil, 200, false},
		{packagePath, http.MethodGet, "deny", "", "deny", "policy", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, nil, 403, false},
		{packagePath, http.MethodGet, "deny", "", "allow", "cache", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Audit: true}, nil, 200, false},
		{packagePath, http.MethodGet, "unavailable", "timeout", "allow", "cache", packagepolicy.Decision{Audit: true}, context.DeadlineExceeded, 200, false},
		{packagePath, http.MethodGet, "unavailable", "provider_error", "allow", "cache", packagepolicy.Decision{}, errors.New("secret-provider-response"), 200, false},
		{packagePath + "?token=secret-query-token", http.MethodGet, "allow", "", "allow", "origin", packagepolicy.Decision{Verdict: packagepolicy.VerdictAllow}, nil, 200, false},
		{packagePath, http.MethodGet, "pending", "", "deny", "policy", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, OriginalVerdict: packagepolicy.VerdictPending}, nil, 403, false},
		{packagePath, http.MethodGet, "deny", "overloaded", "deny", "policy", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, packagepolicy.ErrOverloaded, 503, false},
		{privatePath, http.MethodGet, "not_applicable", "", "allow", "origin", packagepolicy.Decision{Verdict: packagepolicy.VerdictNotApplicable}, nil, 200, true},
		{"/npm/repository/package/-/different-1.0.0.tgz", http.MethodGet, "deny", "unmappable_package", "deny", "policy", packagepolicy.Decision{}, nil, 403, false},
	}
	for _, test := range tests {
		policy.decision, policy.err = test.decision, test.err
		request := httptest.NewRequest(test.method, codeArtifactPath(origin, test.path), nil).WithContext(ctx)
		request.Header.Set("X-User", "untrusted-person@example.com")
		request.Header.Set("Authorization", "Bearer secret-request-token")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		assert.Equal(t, test.status, response.Code)
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		path := packagePath
		if method == http.MethodGet {
			path = "/npm/repository/package"
		}
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, codeArtifactPath(origin, path), nil).WithContext(ctx))
	}
	assert.NoError(t, sink.Close(context.Background()))
	files, err := filepath.Glob(filepath.Join(directory, "*.ndjson"))
	assert.NoError(t, err)
	var events []packageaudit.Event
	for _, path := range files {
		data, err := os.ReadFile(path)
		assert.NoError(t, err)
		for _, forbidden := range []string{"@private", "%40private", "different-1.0.0", "secret-provider-response", "secret-request-token", "secret-query-token", "untrusted-person", origin.URL} {
			assert.False(t, strings.Contains(string(data), forbidden), "unexpected sensitive field", forbidden)
		}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		for decoder.More() {
			var event packageaudit.Event
			assert.NoError(t, decoder.Decode(&event))
			events = append(events, event)
		}
	}
	assert.Equal(t, len(tests), len(events))
	ids := make(map[string]bool)
	for i, event := range events {
		test := tests[i]
		assert.Equal(t, test.verdict, event.PolicyVerdict)
		assert.Equal(t, test.policyError, event.PolicyError)
		assert.Equal(t, test.action, event.PolicyAction)
		assert.Equal(t, test.source, event.ResponseSource)
		assert.Equal(t, test.status, event.HTTPStatus)
		assert.Equal(t, test.decision.VerdictCacheHit, event.VerdictCacheHit)
		assert.Equal(t, test.redacted, event.PackageRedacted)
		assert.Equal(t, "unknown", event.ActorType)
		assert.False(t, ids[event.EventID])
		ids[event.EventID] = true
		if test.redacted || test.policyError == "unmappable_package" {
			assert.Equal(t, "", event.PURL)
		} else {
			assert.Equal(t, purl, event.PURL)
		}
	}
}

func TestCodeArtifactAuditSeparatesPolicyResultFromError(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	tests := []struct {
		name, purl, verdict, policyError string
		decision                         packagepolicy.Decision
		err                              error
		redacted                         bool
	}{
		{"unmappable", "", "deny", "unmappable_package", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, packagepolicy.ErrUnmappablePackage, false},
		{"encoded separator", "", "deny", "unmappable_package", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, packagepolicy.ErrEncodedSeparator, false},
		{"overload", purl, "deny", "overloaded", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, packagepolicy.ErrOverloaded, false},
		{"provider timeout", purl, "unavailable", "timeout", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, context.DeadlineExceeded, false},
		{"provider error", purl, "unavailable", "provider_error", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, errors.New("provider failed"), false},
		{"circuit open", purl, "unavailable", "circuit_open", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, packagepolicy.ErrCircuitOpen, false},
		{"canceled after exclusion", purl, "not_applicable", "canceled", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, OriginalVerdict: packagepolicy.VerdictNotApplicable}, context.Canceled, true},
		{"canceled after allow", purl, "allow", "canceled", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, OriginalVerdict: packagepolicy.VerdictAllow, VerdictCacheHit: true}, context.Canceled, false},
		{"canceled without verdict", purl, "not_evaluated", "canceled", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny}, context.Canceled, false},
		{"request deadline after allow", purl, "allow", "timeout", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, OriginalVerdict: packagepolicy.VerdictAllow, Reasons: []string{"requestCanceled"}}, context.DeadlineExceeded, false},
		{"request deadline without verdict", purl, "not_evaluated", "timeout", packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Reasons: []string{"requestCanceled"}}, context.DeadlineExceeded, false},
	}
	for _, mode := range []string{packagepolicy.ModeEnforce, packagepolicy.ModeAudit} {
		for _, test := range tests {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				decision := test.decision
				decision.Audit = mode == packagepolicy.ModeAudit
				event := codeArtifactAuditEvent(test.purl, decision, errors.Wrap(test.err, "evaluate package policy"))
				assert.Equal(t, mode, event.PolicyMode)
				assert.Equal(t, test.verdict, event.PolicyVerdict)
				assert.Equal(t, test.policyError, event.PolicyError)
				assert.Equal(t, test.redacted, event.PackageRedacted)
				assert.Equal(t, decision.VerdictCacheHit, event.VerdictCacheHit)
				action := "deny"
				if decision.Audit {
					action = "allow"
				}
				assert.Equal(t, action, event.PolicyAction)
				expectedPURL := test.purl
				if test.redacted {
					expectedPURL = ""
				}
				assert.Equal(t, expectedPURL, event.PURL)
			})
		}
	}
}
