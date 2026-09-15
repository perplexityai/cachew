package packagepolicy_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/packagepolicy"
)

func TestPackageURLForCodeArtifact(t *testing.T) {
	tests := []struct {
		name string
		path string
		purl string
		err  error
	}{
		{
			name: "npm package",
			path: "/npm/repository/chromatitle-js/-/chromatitle-js-1.0.0.tgz",
			purl: "pkg:npm/chromatitle-js@1.0.0",
		},
		{
			name: "scoped npm package",
			path: "/npm/repository/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz",
			purl: "pkg:npm/%40ctrl/tinycolor@4.1.1",
		},
		{
			name: "scoped npm package with encoded scope",
			path: "/npm/repository/%40ctrl/tinycolor/-/tinycolor-4.1.1.tgz",
			purl: "pkg:npm/%40ctrl/tinycolor@4.1.1",
		},
		{
			name: "scoped npm package with encoded scope separator",
			path: "/npm/repository/@ctrl%2Ftinycolor/-/tinycolor-4.1.1.tgz",
			purl: "pkg:npm/%40ctrl/tinycolor@4.1.1",
		},
		{
			name: "double-encoded separator is not decoded twice",
			path: "/npm/repository/package%252Fname/-/package%252Fname-1.0.0.tgz",
			purl: "pkg:npm/package%252Fname@1.0.0",
		},
		{
			name: "npm build metadata",
			path: "/npm/repository/package/-/package-1.0.0+build.42.tgz",
			purl: "pkg:npm/package@1.0.0%2Bbuild.42",
		},
		{
			name: "format segment is case-insensitive",
			path: "/NPM/repository/chromatitle-js/-/chromatitle-js-1.0.0.tgz",
			purl: "pkg:npm/chromatitle-js@1.0.0",
		},
		{
			name: "ordinary repository named d is not a routing prefix",
			path: "/npm/d/example-123456789012/-/example-123456789012-1.0.0.tgz",
			purl: "pkg:npm/example-123456789012@1.0.0",
		},
		{name: "npm metadata", path: "/npm/repository/chromatitle-js", err: packagepolicy.ErrNotApplicable},
		{name: "scoped npm metadata with encoded scope separator", path: "/npm/repository/@ctrl%2Ftinycolor", err: packagepolicy.ErrNotApplicable},
		{name: "unmappable npm body", path: "/npm/repository/package/-/different-1.0.0.tgz", err: packagepolicy.ErrUnmappablePackage},
		{name: "empty segment in package body", path: "/npm/repository/package//-/package-1.0.0.tgz", err: packagepolicy.ErrUnmappablePackage},
		{name: "PyPI body passes through", path: "/pypi/repository/simple/requests/2.32.3/requests-2.32.3-py3-none-any.whl", err: packagepolicy.ErrNotApplicable},
		{name: "PyPI encoded path passes through", path: "/pypi/repository/simple/requests%2F..%2F..%2Fevil/1.0.0/evil-1.0.0.whl", err: packagepolicy.ErrNotApplicable},
		{name: "Maven body passes through", path: "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar", err: packagepolicy.ErrNotApplicable},
		{name: "Maven encoded path passes through", path: "/maven/repository/com%2Fperplexity/tool/1.2.3/tool-1.2.3.jar", err: packagepolicy.ErrNotApplicable},
		{name: "Cargo body passes through", path: "/cargo/repository/crates/serde/1.0.210", err: packagepolicy.ErrNotApplicable},
		{name: "Cargo encoded path passes through", path: "/cargo/repository/crates/se%2Frde/1.0.210", err: packagepolicy.ErrNotApplicable},
		{name: "Go CodeArtifact body passes through", path: "/go/repository/github.com/pkg/errors/@v/v0.9.1.zip", err: packagepolicy.ErrNotApplicable},
		{name: "unsupported format", path: "/nuget/repository/v3/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", err: packagepolicy.ErrNotApplicable},
		{name: "encoded separator in an unsupported format passes through", path: "/nuget/repository/a%2Fb/c", err: packagepolicy.ErrNotApplicable},
		{name: "encoded separator in an unscoped npm name is denied", path: "/npm/repository/package%2Fname/-/package%2Fname-1.0.0.tgz", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded traversal is denied", path: "/npm/repository/safe%2F..%2F..%2Fevil/-/evil-1.0.0.tgz", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded scope separator outside the package-name position is denied", path: "/npm/@scope%2Frepo/tinycolor/-/tinycolor-4.1.1.tgz", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded scope separator in the filename is denied", path: "/npm/repository/tinycolor/-/@x%2Ftinycolor-4.1.1.tgz", err: packagepolicy.ErrEncodedSeparator},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, host := range []string{"codeartifact.example.com", "vpce-test.codeartifact.repositories.us-east-1.vpce.amazonaws.com"} {
				path := test.path
				if strings.HasSuffix(host, ".vpce.amazonaws.com") {
					format, rest, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
					path = "/" + format + "/d/example-123456789012/" + rest
				}
				origin, err := url.Parse("https://" + host + path)
				assert.NoError(t, err)
				purl, err := packagepolicy.PackageURLForCodeArtifact(origin)
				if test.err != nil {
					assert.IsError(t, err, test.err)
				} else {
					assert.NoError(t, err)
				}
				assert.Equal(t, test.purl, purl)
			}
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
		{
			name: "incompatible version",
			path: "/github.com/docker/docker/@v/v25.0.0+incompatible.zip",
			purl: "pkg:golang/github.com/docker/docker@v25.0.0%2Bincompatible",
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
