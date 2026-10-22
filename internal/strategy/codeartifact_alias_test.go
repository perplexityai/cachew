package strategy //nolint:testpackage // Validate alias templates at configuration boundaries.

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestCodeArtifactAliasRejectsUnsafeConfiguration(t *testing.T) {
	for _, alias := range []CodeArtifactAliasConfig{
		{Pattern: "/downloads/{name}", Path: "https://example.com/{name}"},
		{Pattern: "/downloads/{name}", Path: "/maven/{unknown}"},
		{Pattern: "/downloads/{name}", Path: "/maven/../{name}"},
		{Pattern: "/downloads/{name}", Path: "/maven/{name}?secret=x"},
		{Pattern: "/downloads/{name...}", Path: "/maven/{name}"},
		{Pattern: "/downloads/{name}/{name}", Path: "/maven/{name}"},
	} {
		_, err := validateCodeArtifactAlias(alias)
		assert.Error(t, err)
	}
}
