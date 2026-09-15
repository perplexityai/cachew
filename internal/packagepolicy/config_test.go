package packagepolicy_test

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/packagepolicy"
)

type policyConfigEnvelope struct {
	PackagePolicy *packagepolicy.Config `hcl:"package-policy,block,optional"`
}

func TestPackagePolicyConfigRoundTripsThroughHCL(t *testing.T) {
	input := []byte(`
package-policy {
  mode = "audit"
  exclude-purls = ["pkg:npm/%40pplx-internal/*", "pkg:npm/@pplx-private/*"]
  on-failure = "deny"
  verdict-ttl = "5m"
  pending-ttl = "20s"

  socket {
    api-url      = "https://socket.example.com"
    organization = "example-org"
    token        = "test-token"
    timeout      = "45s"
    queue-timeout = "250ms"
    label        = "cachew-rollout"
  }
}
`)
	var config policyConfigEnvelope
	assert.NoError(t, hcl.Unmarshal(input, &config))
	assert.NotZero(t, config.PackagePolicy)
	assert.Equal(t, "audit", config.PackagePolicy.Mode)
	assert.Equal(t, "deny", config.PackagePolicy.OnFailure)
	assert.Equal(t, 5*time.Minute, config.PackagePolicy.VerdictTTL)
	assert.Equal(t, 20*time.Second, config.PackagePolicy.PendingTTL)
	assert.Equal(t, []string{"pkg:npm/%40pplx-internal/*", "pkg:npm/@pplx-private/*"}, config.PackagePolicy.ExcludePURLs)
	assert.Equal(t, &packagepolicy.SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: "example-org",
		Token:        "test-token",
		Timeout:      45 * time.Second,
		QueueTimeout: 250 * time.Millisecond,
		Label:        "cachew-rollout",
	}, config.PackagePolicy.Socket)

	encoded, err := hcl.Marshal(&config)
	assert.NoError(t, err)
	var roundTripped policyConfigEnvelope
	assert.NoError(t, hcl.Unmarshal(encoded, &roundTripped))
	assert.Equal(t, config, roundTripped)
}

func TestPackagePolicyConfigIsOptional(t *testing.T) {
	var config policyConfigEnvelope
	assert.NoError(t, hcl.Unmarshal(nil, &config))
	assert.Zero(t, config.PackagePolicy)
}

func TestPackagePolicyModeAndDefaults(t *testing.T) {
	var config policyConfigEnvelope
	assert.NoError(t, hcl.Unmarshal([]byte(`package-policy { socket { organization = "example" token = "test-token" } }`), &config))
	assert.Equal(t, "enforce", config.PackagePolicy.Mode)
	assert.Equal(t, 15*time.Second, config.PackagePolicy.PendingTTL)
	assert.Equal(t, 100*time.Millisecond, config.PackagePolicy.Socket.QueueTimeout)
	_, err := packagepolicy.New(*config.PackagePolicy)
	assert.NoError(t, err)

	evaluator, err := packagepolicy.New(packagepolicy.Config{Mode: "disabled"})
	assert.NoError(t, err)
	assert.Zero(t, evaluator)
	for _, mode := range []string{"", "monitor"} {
		_, err = packagepolicy.New(packagepolicy.Config{Mode: mode})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mode must be disabled, audit or enforce")
	}
}
