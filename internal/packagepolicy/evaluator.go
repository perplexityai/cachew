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
	patterns := make([]string, 0, len(config.ExcludePURLs))
	for _, pattern := range config.ExcludePURLs {
		if !slices.ContainsFunc(supportedTypes, func(prefix string) bool { return strings.HasPrefix(pattern, prefix) }) {
			return nil, errors.New("package policy: exclude-purls supports only npm, PyPI, Maven, and Cargo PURLs")
		}
		// Cachew emits npm scopes as %40; accept the natural @scope spelling so a private scope is not
		// silently sent to the provider because of an encoding mismatch.
		pattern = normalizePyPIPattern(strings.Replace(pattern, "pkg:npm/@", "pkg:npm/%40", 1))
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, errors.Wrap(err, "package policy: invalid exclude-purls pattern")
		}
		patterns = append(patterns, pattern)
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
	if len(patterns) > 0 {
		evaluator = &excludingEvaluator{Evaluator: evaluator, patterns: patterns}
	}
	return evaluator, nil
}

// normalizePyPIPattern applies the PURL name normalization to a PyPI pattern so a private project
// written with its published spelling is not sent to the provider because of a case or separator
// mismatch.
func normalizePyPIPattern(pattern string) string {
	rest, ok := strings.CutPrefix(pattern, "pkg:pypi/")
	if !ok {
		return pattern
	}
	name, version, hasVersion := strings.Cut(rest, "@")
	name = pypiNormalizationPattern.ReplaceAllString(strings.ToLower(name), "-")
	if hasVersion {
		return "pkg:pypi/" + name + "@" + version
	}
	return "pkg:pypi/" + name
}

// failClosedEvaluator turns provider failures and pending analysis into denials for on-failure = "deny".
type failClosedEvaluator struct {
	Evaluator
}

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
	return e.Evaluator.Evaluate(ctx, purl) //nolint:wrapcheck // The inner decorators already prefix the error.
}
