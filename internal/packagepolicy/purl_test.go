package packagepolicy_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/packagepolicy"
)

func TestPackageURLForCodeArtifact(t *testing.T) {
	tests := []struct {
		name string
		path string
		purl string
		ok   bool
	}{
		{
			name: "npm package",
			path: "/npm/repository/chromatitle-js/-/chromatitle-js-1.0.0.tgz",
			purl: "pkg:npm/chromatitle-js@1.0.0",
			ok:   true,
		},
		{
			name: "scoped npm package",
			path: "/npm/repository/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz",
			purl: "pkg:npm/%40ctrl/tinycolor@4.1.1",
			ok:   true,
		},
		{
			name: "PyPI wheel",
			path: "/pypi/repository/simple/requests/2.32.3/requests-2.32.3-py3-none-any.whl",
			purl: "pkg:pypi/requests@2.32.3",
			ok:   true,
		},
		{
			name: "PyPI normalized package",
			path: "/pypi/repository/simple/My_Package/1.0.0/My_Package-1.0.0.tar.gz",
			purl: "pkg:pypi/my-package@1.0.0",
			ok:   true,
		},
		{
			name: "double-encoded separator is not decoded twice",
			path: "/npm/repository/package%2Fname/-/package%2Fname-1.0.0.tgz",
			purl: "pkg:npm/package%252Fname@1.0.0",
			ok:   true,
		},
		{name: "npm metadata", path: "/npm/repository/chromatitle-js", ok: false},
		{name: "PyPI metadata", path: "/pypi/repository/simple/requests/", ok: false},
		{name: "unsupported format", path: "/maven/repository/example.jar", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			purl, ok := packagepolicy.PackageURLForCodeArtifact(test.path)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.purl, purl)
		})
	}
}

func TestPackageURLForGoModule(t *testing.T) {
	tests := []struct {
		name string
		path string
		purl string
		ok   bool
	}{
		{
			name: "module zip",
			path: "/github.com/pkg/errors/@v/v0.9.1.zip",
			purl: "pkg:golang/github.com/pkg/errors@v0.9.1",
			ok:   true,
		},
		{
			name: "escaped uppercase module",
			path: "/github.com/!azure/azure-sdk-for-go/@v/v1.2.3.mod",
			purl: "pkg:golang/github.com/Azure/azure-sdk-for-go@v1.2.3",
			ok:   true,
		},
		{
			name: "canonical pseudo-version",
			path: "/github.com/pkg/errors/@v/v0.0.0-20200101000000-abcdefabcdef.info",
			purl: "pkg:golang/github.com/pkg/errors@v0.0.0-20200101000000-abcdefabcdef",
			ok:   true,
		},
		{name: "branch query", path: "/github.com/pkg/errors/@v/master.info", ok: false},
		{name: "commit query", path: "/github.com/pkg/errors/@v/abcdef1234567890.info", ok: false},
		{name: "version list", path: "/github.com/pkg/errors/@v/list", ok: false},
		{name: "latest", path: "/github.com/pkg/errors/@latest", ok: false},
		{name: "invalid", path: "/not-a-module", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			purl, ok := packagepolicy.PackageURLForGoModule(test.path)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.purl, purl)
		})
	}
}
