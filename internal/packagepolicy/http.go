package packagepolicy

import (
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/alecthomas/errors"
)

var safeReasonPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const policyHeader = "X-Cachew-Package-Policy"

// AllowRequest reports whether an HTTP package request may continue and writes
// a response only for an explicit denial. Provider failures and pending analysis
// fail open unless the evaluator already converted them into a denial; the
// pass-through response is labelled so clients and logs can see it was unchecked.
func AllowRequest(w http.ResponseWriter, decision Decision, err error) bool {
	if decision.Verdict != VerdictDeny {
		switch {
		case err != nil:
			w.Header().Set(policyHeader, "unavailable")
		case decision.Verdict == VerdictPending:
			w.Header().Set(policyHeader, "pending")
		}
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(policyHeader, "deny")
	message := "Package denied by security policy"
	if reasons := safeReasons(decision.Reasons); len(reasons) > 0 {
		message += ": " + strings.Join(reasons, ", ")
	}
	http.Error(w, message, http.StatusForbidden)
	return false
}

// LogLevel keeps per-request logs below error level when they do not indicate a Cachew or provider
// fault: a skipped provider repeats on every request during an outage that the metric already
// reports, and an encoded separator is a malformed client request.
func LogLevel(err error) slog.Level {
	if errors.Is(err, ErrCircuitOpen) || errors.Is(err, ErrEncodedSeparator) {
		return slog.LevelWarn
	}
	return slog.LevelError
}

// Cacheable reports whether a response served under this decision may be admitted to the cache.
// Fail-open responses are not, so a later request re-evaluates the package.
func Cacheable(decision Decision, err error) bool {
	return err == nil && decision.Verdict != VerdictPending
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
