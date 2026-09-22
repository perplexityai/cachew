package strategy

import (
	"context"
	"net/http"
	"slices"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/packageaudit"
	"github.com/block/cachew/internal/packagepolicy"
)

func (c *CodeArtifact) packageAuditEvent(r *http.Request, purl string, decision packagepolicy.Decision, err error) (packageaudit.Event, bool) {
	if c.packageAudit == nil || r.Method != http.MethodGet {
		return packageaudit.Event{}, false
	}
	if c.packagePolicy != nil {
		return codeArtifactAuditEvent(purl, decision, err), purl != "" || err != nil
	}
	origin := c.originURL(r)
	purl, err = packagepolicy.PackageURLForCodeArtifact(&origin)
	if errors.Is(err, packagepolicy.ErrNotApplicable) {
		return packageaudit.Event{}, false
	}
	event := packageaudit.Event{
		PURL: purl, PackageRedacted: c.auditExclusions.Matches(purl),
		PolicyMode: packagepolicy.ModeDisabled, PolicyVerdict: "not_evaluated", PolicyAction: "allow",
	}
	if err != nil {
		event.PolicyError = codeArtifactUnmappablePackage
	}
	return event, true
}

const (
	codeArtifactAuditOrigin       = "origin"
	codeArtifactAuditUnavailable  = "unavailable"
	codeArtifactUnmappablePackage = "unmappable_package"
)

func codeArtifactAuditEvent(purl string, decision packagepolicy.Decision, err error) packageaudit.Event {
	redacted := decision.Verdict == packagepolicy.VerdictNotApplicable ||
		decision.OriginalVerdict == packagepolicy.VerdictNotApplicable
	event := packageaudit.Event{
		PURL:            purl,
		PackageRedacted: redacted,
		PolicyMode:      packagepolicy.ModeEnforce,
		PolicyVerdict:   string(decision.Verdict),
		PolicyAction:    "allow",
		VerdictCacheHit: decision.VerdictCacheHit,
	}
	if decision.OriginalVerdict != "" {
		event.PolicyVerdict = string(decision.OriginalVerdict)
	}
	if event.PolicyVerdict == "" {
		event.PolicyVerdict = "not_evaluated"
	}
	if decision.Audit {
		event.PolicyMode = packagepolicy.ModeAudit
	} else if decision.Verdict == packagepolicy.VerdictDeny || errors.Is(err, packagepolicy.ErrOverloaded) {
		event.PolicyAction = "deny"
	}
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled), slices.Contains(decision.Reasons, "requestCanceled"):
		event.PolicyError = "canceled"
		if errors.Is(err, context.DeadlineExceeded) {
			event.PolicyError = "timeout"
		}
		if decision.OriginalVerdict == "" {
			event.PolicyVerdict = "not_evaluated"
		}
	case errors.Is(err, packagepolicy.ErrOverloaded):
		event.PolicyError = "overloaded"
		event.PolicyVerdict = string(packagepolicy.VerdictDeny)
	case errors.Is(err, packagepolicy.ErrEncodedSeparator), errors.Is(err, packagepolicy.ErrUnmappablePackage):
		event.PolicyError = codeArtifactUnmappablePackage
		event.PolicyVerdict = string(packagepolicy.VerdictDeny)
	case errors.Is(err, packagepolicy.ErrCircuitOpen):
		event.PolicyError = "circuit_open"
		event.PolicyVerdict = codeArtifactAuditUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		event.PolicyError = "timeout"
		if decision.OriginalVerdict == "" {
			event.PolicyVerdict = codeArtifactAuditUnavailable
		}
	default:
		event.PolicyError = "provider_error"
		event.PolicyVerdict = codeArtifactAuditUnavailable
	}
	if event.PackageRedacted {
		event.PURL = ""
	}
	return event
}
