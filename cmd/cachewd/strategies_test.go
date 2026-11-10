package main

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/spool"
)

const awsOriginStartupChildEnv = "CACHEWD_AWS_ORIGIN_STARTUP_CHILD"

// AWS origin strategies tune their own transports, so they must load after
// configureProcess has wrapped http.DefaultTransport. The check runs in a child
// process because configureProcess replaces process-wide state.
func TestAWSOriginStrategiesLoadAfterProcessSetup(t *testing.T) {
	if os.Getenv(awsOriginStartupChildEnv) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), awsOriginStartupChildEnv+"=1")
		output, err := cmd.CombinedOutput()
		assert.NoError(t, err, "%s", output)
		return
	}
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	logger, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	configureProcess(logger, 0, time.Second, time.Minute)

	spools := spool.NewProvider(ctx, spool.Config{Dir: t.TempDir()}, func(error) {})
	cr, mr, sr := newRegistries(nil, nil, nil, nil, spools)
	ast, err := hcl.Parse(strings.NewReader(`
cache memory {}
metadata memory {}
strategy codeartifact "https://example-111122223333.d.codeartifact.us-east-1.amazonaws.com" {
  proxy-base-url = "https://cachew.example.com"
  domain         = "example"
  domain-owner   = "111122223333"
  region         = "us-east-1"
  role-arn       = "arn:aws:iam::111122223333:role/read"
}
strategy ecr "111122223333.dkr.ecr.us-east-1.amazonaws.com" {
  role-arn = "arn:aws:iam::111122223333:role/read"
}
`))
	assert.NoError(t, err)
	var shuttingDown atomic.Bool
	_, err = newMux(ctx, &shuttingDown, cr, mr, sr, ast, nil)
	assert.NoError(t, err)
}
