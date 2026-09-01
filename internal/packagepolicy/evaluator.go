// Package packagepolicy evaluates package URLs before Cachew fetches package bodies.
package packagepolicy

import (
	"context"

	"github.com/alecthomas/errors"
)

// Config selects and configures one package policy provider.
type Config struct {
	Socket *SocketConfig `hcl:"socket,block,optional" help:"Socket organization policy provider."`
}

// Verdict is the policy result for a package URL.
type Verdict string

const (
	VerdictAllow   Verdict = "allow"
	VerdictDeny    Verdict = "deny"
	VerdictPending Verdict = "pending"
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
		return nil, errors.New("package policy: exactly one provider is required")
	}
	return newSocketEvaluator(*config.Socket, false)
}
