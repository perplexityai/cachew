package packagepolicy

import (
	"net/http"
	"regexp"
	"strings"
)

var safeReasonPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// AllowRequest reports whether an HTTP package request may continue and writes
// a response only for an explicit denial. Provider failures fail open.
func AllowRequest(w http.ResponseWriter, decision Decision, err error) bool {
	if err != nil || decision.Verdict != VerdictDeny {
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Cachew-Package-Policy", "deny")
	message := "Package denied by security policy"
	if reasons := safeReasons(decision.Reasons); len(reasons) > 0 {
		message += ": " + strings.Join(reasons, ", ")
	}
	http.Error(w, message, http.StatusForbidden)
	return false
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
