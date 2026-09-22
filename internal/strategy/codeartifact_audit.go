package strategy

import (
	"context"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/packageaudit"
	"github.com/block/cachew/internal/packagepolicy"
)

const codeArtifactAuditOrigin = "origin"

func codeArtifactAuditEvent(purl string, decision packagepolicy.Decision, err error) packageaudit.Event {
	redacted := purl == "" || decision.Verdict == packagepolicy.VerdictNotApplicable ||
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
	if decision.Audit {
		event.PolicyMode = packagepolicy.ModeAudit
	} else if decision.Verdict == packagepolicy.VerdictDeny || errors.Is(err, packagepolicy.ErrOverloaded) {
		event.PolicyAction = "deny"
	}
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		event.PolicyError = "canceled"
	case errors.Is(err, packagepolicy.ErrOverloaded):
		event.PolicyError = "overloaded"
	case errors.Is(err, packagepolicy.ErrCircuitOpen):
		event.PolicyError = "circuit_open"
	case errors.Is(err, context.DeadlineExceeded):
		event.PolicyError = "timeout"
	case errors.Is(err, packagepolicy.ErrEncodedSeparator), errors.Is(err, packagepolicy.ErrUnmappablePackage):
		event.PolicyError = "unmappable_package"
	default:
		event.PolicyError = "provider_error"
	}
	if err != nil {
		event.PolicyVerdict = "unavailable"
	}
	if event.PackageRedacted {
		event.PURL = ""
	}
	return event
}
