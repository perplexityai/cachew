package packagepolicy_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/packagepolicy"
)

func TestLogLevelKeepsNonProviderFaultsBelowError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		level slog.Level
	}{
		{name: "breaker skip", err: packagepolicy.ErrCircuitOpen, level: slog.LevelWarn},
		{name: "encoded separator", err: errors.Wrap(packagepolicy.ErrEncodedSeparator, "evaluate package policy"), level: slog.LevelWarn},
		{name: "caller cancelled", err: errors.Wrap(context.Canceled, "socket policy: wait for shared evaluation"), level: slog.LevelDebug},
		{name: "provider failure", err: errors.New("socket policy: API returned 500"), level: slog.LevelError},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.level, packagepolicy.LogLevel(test.err))
		})
	}
}
