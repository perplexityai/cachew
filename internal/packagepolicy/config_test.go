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
  socket {
    api-url      = "https://socket.example.com"
    organization = "example-org"
    token        = "test-token"
    timeout      = "45s"
  }
}
`)
	var config policyConfigEnvelope
	assert.NoError(t, hcl.Unmarshal(input, &config))
	assert.NotZero(t, config.PackagePolicy)
	assert.Equal(t, &packagepolicy.SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: "example-org",
		Token:        "test-token",
		Timeout:      45 * time.Second,
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
