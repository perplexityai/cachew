package packagepolicy_test

import (
	"net/url"
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
			name: "PyPI wheel",
			path: "/pypi/repository/simple/requests/2.32.3/requests-2.32.3-py3-none-any.whl",
			purl: "pkg:pypi/requests@2.32.3",
		},
		{
			name: "PyPI normalized package",
			path: "/pypi/repository/simple/My_Package/1.0.0/My_Package-1.0.0.tar.gz",
			purl: "pkg:pypi/my-package@1.0.0",
		},
		{
			name: "Maven jar",
			path: "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar",
			purl: "pkg:maven/com.perplexity/tool@1.2.3",
		},
		{
			name: "Maven pom shares the artifact coordinate",
			path: "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.pom",
			purl: "pkg:maven/com.perplexity/tool@1.2.3",
		},
		{
			name: "Cargo crate",
			path: "/cargo/repository/crates/serde/1.0.210",
			purl: "pkg:cargo/serde@1.0.210",
		},
		{
			name: "format segment is case-insensitive",
			path: "/NPM/repository/chromatitle-js/-/chromatitle-js-1.0.0.tgz",
			purl: "pkg:npm/chromatitle-js@1.0.0",
		},
		{name: "npm metadata", path: "/npm/repository/chromatitle-js", err: packagepolicy.ErrNotApplicable},
		{name: "scoped npm metadata with encoded scope separator", path: "/npm/repository/@ctrl%2Ftinycolor", err: packagepolicy.ErrNotApplicable},
		{name: "PyPI metadata", path: "/pypi/repository/simple/requests/", err: packagepolicy.ErrNotApplicable},
		{name: "Maven metadata", path: "/maven/repository/com/perplexity/tool/maven-metadata.xml", err: packagepolicy.ErrNotApplicable},
		{name: "Maven snapshot", path: "/maven/repository/com/perplexity/tool/1.2.3-SNAPSHOT/tool-1.2.3-SNAPSHOT.jar", err: packagepolicy.ErrNotApplicable},
		{name: "Cargo index", path: "/cargo/repository/config.json", err: packagepolicy.ErrNotApplicable},
		{name: "unsupported format", path: "/nuget/repository/v3/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", err: packagepolicy.ErrNotApplicable},
		{name: "encoded separator in an unsupported format passes through", path: "/nuget/repository/a%2Fb/c", err: packagepolicy.ErrNotApplicable},
		{name: "encoded separator in an unscoped npm name is denied", path: "/npm/repository/package%2Fname/-/package%2Fname-1.0.0.tgz", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded traversal is denied", path: "/pypi/repository/simple/requests%2F..%2F..%2Fevil/1.0.0/evil-1.0.0.whl", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded separator in a Maven group is denied", path: "/maven/repository/com%2Fperplexity/tool/1.2.3/tool-1.2.3.jar", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded scope separator outside the package-name position is denied", path: "/npm/@scope%2Frepo/tinycolor/-/tinycolor-4.1.1.tgz", err: packagepolicy.ErrEncodedSeparator},
		{name: "encoded scope separator in the filename is denied", path: "/npm/repository/tinycolor/-/@x%2Ftinycolor-4.1.1.tgz", err: packagepolicy.ErrEncodedSeparator},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			purl, err := packagepolicy.PackageURLForCodeArtifact(escapedPath(t, test.path))
			if test.err != nil {
				assert.IsError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.purl, purl)
		})
	}
}

// escapedPath models production, where the strategy passes the request's escaped path.
func escapedPath(t *testing.T, path string) string {
	t.Helper()
	parsed, err := url.Parse("https://codeartifact.example.com" + path)
	assert.NoError(t, err)
	return parsed.EscapedPath()
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
