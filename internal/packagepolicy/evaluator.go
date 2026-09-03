// Package packagepolicy evaluates package URLs before Cachew fetches package bodies.
package packagepolicy

import (
	"context"
	"path"
	"strings"

	"github.com/alecthomas/errors"
)

// Config selects and configures one package policy provider.
type Config struct {
	ExcludePURLs []string      `hcl:"exclude-purls,optional" help:"npm and PyPI PURL glob patterns to exclude before provider evaluation."`
	Socket       *SocketConfig `hcl:"socket,block,optional" help:"Socket organization policy provider."`
}

// Verdict is the policy result for a package URL.
type Verdict string

const (
	VerdictAllow   Verdict = "allow"
	VerdictDeny    Verdict = "deny"
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
	Evaluate(context.Context, string) (Decision, error)
	ObserveNotApplicable(context.Context)
}

// New creates the configured package policy evaluator.
func New(config Config) (Evaluator, error) {
	if config.Socket == nil {
		return nil, errors.New("package policy: provider is required")
	}
	for _, pattern := range config.ExcludePURLs {
		if !strings.HasPrefix(pattern, "pkg:npm/") && !strings.HasPrefix(pattern, "pkg:pypi/") {
			return nil, errors.New("package policy: exclude-purls supports only npm and PyPI PURLs")
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, errors.Wrap(err, "package policy: invalid exclude-purls pattern")
		}
	}
	evaluator, err := newSocketEvaluator(*config.Socket, false)
	if err != nil || len(config.ExcludePURLs) == 0 {
		return evaluator, err
	}
	return &excludingEvaluator{Evaluator: evaluator, patterns: config.ExcludePURLs}, nil
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
	decision, err := e.Evaluator.Evaluate(ctx, purl)
	if err != nil {
		return Decision{}, errors.Wrap(err, "package policy: evaluate provider")
	}
	return decision, nil
}
