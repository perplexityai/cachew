package packagepolicy

import (
	"net/http"
	"regexp"
	"strings"
)

var safeReasonPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// AllowRequest reports whether an HTTP package request may continue and writes a
// fail-closed response when the decision is not an allow.
func AllowRequest(w http.ResponseWriter, decision Decision, err error) bool {
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Cachew-Package-Policy", "unavailable")
		http.Error(w, "Package security policy unavailable", http.StatusServiceUnavailable)
		return false
	}
	switch decision.Verdict {
	case VerdictAllow:
		return true
	case VerdictDeny:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Cachew-Package-Policy", "deny")
		message := "Package denied by security policy"
		if reasons := safeReasons(decision.Reasons); len(reasons) > 0 {
			message += ": " + strings.Join(reasons, ", ")
		}
		http.Error(w, message, http.StatusForbidden)
		return false
	case VerdictPending:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Cachew-Package-Policy", "pending")
		w.Header().Set("Retry-After", "5")
		http.Error(w, "Package security analysis pending", http.StatusServiceUnavailable)
		return false
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Cachew-Package-Policy", "unavailable")
		http.Error(w, "Package security policy unavailable", http.StatusServiceUnavailable)
		return false
	}
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
