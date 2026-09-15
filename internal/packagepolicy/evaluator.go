// Package packagepolicy evaluates package URLs before Cachew fetches package bodies.
package packagepolicy

import (
	"context"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/errors"
)

// Config selects and configures one package policy provider.
type Config struct {
	ExcludePURLs []string      `hcl:"exclude-purls,optional" help:"npm, PyPI, Maven, and Cargo PURL glob patterns to exclude before provider evaluation."`
	VerdictTTL   time.Duration `hcl:"verdict-ttl,optional" help:"How long allow and deny verdicts are reused before the provider is asked again. Zero disables the verdict cache." default:"10m"`
	OnFailure    string        `hcl:"on-failure,optional" help:"allow continues to the origin when the provider is unavailable or analysis is pending; deny returns 403 instead." default:"allow"`
	Socket       *SocketConfig `hcl:"socket,block,optional" help:"Socket organization policy provider."`
}

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
	if config.Socket == nil {
		return nil, errors.New("package policy: provider is required")
	}
	supportedTypes := []string{"pkg:npm/", "pkg:pypi/", "pkg:maven/", "pkg:cargo/"}
	for _, pattern := range config.ExcludePURLs {
		if !slices.ContainsFunc(supportedTypes, func(prefix string) bool { return strings.HasPrefix(pattern, prefix) }) {
			return nil, errors.New("package policy: exclude-purls supports only npm, PyPI, Maven, and Cargo PURLs")
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, errors.Wrap(err, "package policy: invalid exclude-purls pattern")
		}
	}
	if config.OnFailure != "" && config.OnFailure != "allow" && config.OnFailure != "deny" {
		return nil, errors.Errorf("package policy: on-failure must be allow or deny, got %q", config.OnFailure)
	}
	if config.VerdictTTL < 0 {
		return nil, errors.New("package policy: verdict-ttl must not be negative")
	}
	socket, err := newSocketEvaluator(*config.Socket, false)
	if err != nil {
		return nil, err
	}
	var evaluator Evaluator = socket
	if config.VerdictTTL > 0 {
		evaluator = newCachingEvaluator(evaluator, config.VerdictTTL, socket.metrics)
	}
	if config.OnFailure == "deny" {
		evaluator = failClosedEvaluator{Evaluator: evaluator}
	}
	if len(config.ExcludePURLs) > 0 {
		evaluator = &excludingEvaluator{Evaluator: evaluator, patterns: config.ExcludePURLs}
	}
	return evaluator, nil
}

// failClosedEvaluator turns provider failures and pending analysis into denials for on-failure = "deny".
type failClosedEvaluator struct {
	Evaluator
}

// Evaluate keeps the provider error so callers can still log the cause of a denial.
func (e failClosedEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	decision, err := e.Evaluator.Evaluate(ctx, purl)
	if err != nil {
		return Decision{Verdict: VerdictDeny, Reasons: []string{"unavailable"}}, errors.Wrap(err, "package policy: fail closed")
	}
	if decision.Verdict == VerdictPending {
		return Decision{Verdict: VerdictDeny, Reasons: decision.Reasons}, nil
	}
	return decision, nil
}

type excludingEvaluator struct {
	Evaluator
	patterns []string
}

// Evaluate keeps excluded package coordinates out of the provider request.
func (e *excludingEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	for _, pattern := range e.patterns {
		matched, err := path.Match(pattern, purl)
		if err != nil {
			return Decision{}, errors.Wrap(err, "package policy: match exclude-purls pattern")
		}
		if matched {
			e.ObserveNotApplicable(ctx)
			return Decision{Verdict: VerdictNotApplicable}, nil
		}
	}
	decision, err := e.Evaluator.Evaluate(ctx, purl)
	if err != nil {
		return decision, errors.Wrap(err, "package policy: evaluate provider")
	}
	return decision, nil
}
