package packagepolicy

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/alecthomas/errors"
)

var safeReasonPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const policyHeader = "X-Cachew-Package-Policy"

// AllowRequest enforces denials and local overload, or reports a non-blocking audit outcome.
// Provider failures and pending analysis fail open unless already converted into a denial.
func AllowRequest(w http.ResponseWriter, decision Decision, err error) bool {
	if decision.Audit {
		outcome := "audit-would_allow"
		if decision.Verdict == VerdictDeny || errors.Is(err, ErrOverloaded) {
			outcome = "audit-would_deny"
		}
		w.Header().Set(policyHeader, outcome)
		return true
	}
	if errors.Is(err, ErrOverloaded) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(policyHeader, "overloaded")
		http.Error(w, "Package policy capacity unavailable", http.StatusServiceUnavailable)
		return false
	}
	if decision.Verdict != VerdictDeny {
		switch {
		case err != nil:
			w.Header().Set(policyHeader, outcomeUnavailable)
		case decision.Verdict == VerdictPending:
			w.Header().Set(policyHeader, "pending")
		}
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(policyHeader, string(VerdictDeny))
	message := "Package denied by security policy"
	if reasons := safeReasons(decision.Reasons); len(reasons) > 0 {
		message += ": " + strings.Join(reasons, ", ")
	}
	http.Error(w, message, http.StatusForbidden)
	return false
}

// LogLevel keeps per-request logs below error level when they do not indicate a Cachew or provider
// fault: a skipped provider repeats on every request during an outage that the metric already
// reports, an encoded separator is a malformed client request, and a cancelled context means the
// client left before the provider answered.
func LogLevel(err error) slog.Level {
	switch {
	case errors.Is(err, context.Canceled):
		return slog.LevelDebug
	case errors.Is(err, ErrCircuitOpen), errors.Is(err, ErrOverloaded), errors.Is(err, ErrEncodedSeparator):
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

// Cacheable reports whether a response served under this decision may be admitted to the cache.
// Audit leaves caching unchanged; enforce admits only approved or out-of-scope responses.
func Cacheable(decision Decision, err error) bool {
	return decision.Audit || (err == nil && decision.Verdict != VerdictPending && decision.Verdict != VerdictDeny)
}

func safeReasons(reasons []string) []string {
	safe := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if safeReasonPattern.MatchString(reason) {
			safe = append(safe, reason)
		}
	}
	return safe
}
