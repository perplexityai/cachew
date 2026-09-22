// Package packagepolicy evaluates package URLs before Cachew fetches package bodies.
package packagepolicy

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/alecthomas/errors"
)

// Config selects and configures one package policy provider.
type Config struct {
	Mode         string        `hcl:"mode,optional" help:"disabled skips policy; audit reports decisions without enforcement; enforce applies decisions." default:"enforce"`
	ExcludePURLs []string      `hcl:"exclude-purls,optional" help:"npm PURL glob patterns to exclude before provider evaluation."`
	VerdictTTL   time.Duration `hcl:"verdict-ttl,optional" help:"Maximum age of reused allow and deny verdicts; capacity eviction may remove them earlier. Zero disables definitive verdict reuse." default:"10m"`
	PendingTTL   time.Duration `hcl:"pending-ttl,optional" help:"Maximum age of reused pending results and provider errors. Zero disables temporary result reuse." default:"15s"`
	OnFailure    string        `hcl:"on-failure,optional" help:"allow continues to the origin when the provider is unavailable or analysis is pending; deny returns 403 instead." default:"allow"`
	Socket       *SocketConfig `hcl:"socket,block,optional" help:"Socket organization policy provider."`
}

const (
	// ModeDisabled skips package policy evaluation.
	ModeDisabled = "disabled"
	// ModeAudit evaluates policy without changing artifact serving or caching.
	ModeAudit = "audit"
	// ModeEnforce applies package policy decisions before serving artifacts.
	ModeEnforce = "enforce"
)

// Verdict is the policy result for a package URL.
type Verdict string

const (
	// VerdictAllow permits the package.
	VerdictAllow Verdict = "allow"
	// VerdictDeny rejects the package.
	VerdictDeny Verdict = "deny"
	// VerdictPending indicates that the provider has not completed analysis.
	VerdictPending Verdict = "pending"
	// VerdictNotApplicable distinguishes privacy exclusions from provider-approved packages.
	VerdictNotApplicable Verdict = "not_applicable"
)

// Decision is an aggregated package policy result.
type Decision struct {
	Verdict Verdict
	Reasons []string
	// OriginalVerdict preserves the result before local fail-closed or cancellation handling.
	OriginalVerdict Verdict
	// VerdictCacheHit describes this request, not whether a provider call was coalesced.
	VerdictCacheHit bool
	// Audit reports the enforcement outcome without changing artifact serving or caching.
	Audit bool
}

// Evaluator checks package URLs against a package policy.
type Evaluator interface {
	// Evaluate separates policy decisions from provider failures so callers can choose fail-open behavior.
	Evaluate(context.Context, string) (Decision, error)
	// ObserveNotApplicable keeps bypassed requests visible without sending package coordinates to the provider.
	ObserveNotApplicable(context.Context)
}

// New creates the configured package policy evaluator.
func New(config Config) (Evaluator, error) {
	switch config.Mode {
	case ModeDisabled:
		return nil, nil //nolint:nilnil // A nil evaluator is the existing strategy contract for disabled policy.
	case ModeAudit, ModeEnforce:
	default:
		return nil, errors.Errorf("package policy: mode must be disabled, audit or enforce, got %q", config.Mode)
	}
	if config.Socket == nil {
		return nil, errors.New("package policy: provider is required")
	}
	patterns, err := NewExclusions(config.ExcludePURLs)
	if err != nil {
		return nil, err
	}
	if config.OnFailure != string(VerdictAllow) && config.OnFailure != string(VerdictDeny) {
		return nil, errors.Errorf("package policy: on-failure must be allow or deny, got %q", config.OnFailure)
	}
	if config.VerdictTTL < 0 {
		return nil, errors.New("package policy: verdict-ttl must not be negative")
	}
	if config.PendingTTL < 0 {
		return nil, errors.New("package policy: pending-ttl must not be negative")
	}
	socket, err := newSocketEvaluator(*config.Socket, false)
	if err != nil {
		return nil, err
	}
	var evaluator Evaluator = socket
	if config.VerdictTTL > 0 || config.PendingTTL > 0 {
		evaluator = newCachingEvaluator(evaluator, config.VerdictTTL, config.PendingTTL, socket.metrics)
	}
	if config.OnFailure == string(VerdictDeny) {
		evaluator = failClosedEvaluator{Evaluator: evaluator}
	}
	if len(config.ExcludePURLs) > 0 {
		evaluator = &excludingEvaluator{Evaluator: evaluator, patterns: patterns}
	}
	return &metricsEvaluator{Evaluator: evaluator, metrics: socket.metrics, audit: config.Mode == ModeAudit}, nil
}

// failClosedEvaluator turns provider failures and pending analysis into denials for on-failure = "deny".
type failClosedEvaluator struct {
	Evaluator
}

func (e failClosedEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	decision, err := e.Evaluator.Evaluate(ctx, purl)
	if errors.Is(err, ErrOverloaded) {
		return decision, err //nolint:wrapcheck // Local overload must keep its distinct response and reason.
	}
	if err != nil {
		decision.Verdict = VerdictDeny
		decision.Reasons = []string{outcomeUnavailable}
		return decision, errors.Wrap(err, "package policy: fail closed")
	}
	if decision.Verdict == VerdictPending {
		decision.OriginalVerdict = decision.Verdict
		decision.Verdict = VerdictDeny
	}
	return decision, nil
}

type excludingEvaluator struct {
	Evaluator
	patterns Exclusions
}

func (e *excludingEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	if e.patterns.Matches(purl) {
		return Decision{Verdict: VerdictNotApplicable}, nil
	}
	return e.Evaluator.Evaluate(ctx, purl) //nolint:wrapcheck // The inner decorators already prefix the error.
}

// Exclusions matches validated npm privacy patterns without constructing a provider.
type Exclusions struct {
	patterns []string
}

// NewExclusions validates npm PURL globs and normalizes natural @scope spelling to emitted %40 scopes.
func NewExclusions(patterns []string) (Exclusions, error) {
	exclusions := Exclusions{}
	for _, pattern := range patterns {
		if !strings.HasPrefix(pattern, "pkg:npm/") {
			return Exclusions{}, errors.New("exclude-purls supports only npm PURLs")
		}
		pattern = strings.Replace(pattern, "pkg:npm/@", "pkg:npm/%40", 1)
		if _, err := path.Match(pattern, ""); err != nil {
			return Exclusions{}, errors.Wrap(err, "invalid exclude-purls pattern")
		}
		exclusions.patterns = append(exclusions.patterns, pattern)
	}
	return exclusions, nil
}

// Matches reports whether a coordinate is excluded. The zero value excludes nothing.
func (e Exclusions) Matches(purl string) bool {
	for _, pattern := range e.patterns {
		matched, err := path.Match(pattern, purl)
		if err == nil && matched {
			return true
		}
	}
	return false
}
