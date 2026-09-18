package strategy //nolint:testpackage // Exercise strict metadata route boundaries.

import (
	"net/url"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestMetadataRouteBoundaries(t *testing.T) {
	for _, tt := range []struct {
		path  string
		valid bool
	}{
		{"/npm/repo/@scope%2Fpackage", true}, {"/npm/repo/@scope/package", true},
		{"/npm/repo/@scope%252Fpackage", false}, {"/npm/repo/react/1.0.0", false},
		{"/pypi/repo/simple/pip/", true}, {"/pypi/repo/simple/my-project/", true},
		{"/pypi/repo/simple/", false}, {"/pypi/repo/simple/pip/file.whl", false},
		{"/pypi/repo/simple/%2E%2E/", false},
		{"/cargo/repo/config.json", true}, {"/cargo/repo/1/a", true}, {"/cargo/repo/2/ab", true},
		{"/cargo/repo/3/a/abc", true}, {"/cargo/repo/se/rd/serde", true},
		{"/cargo/repo/se/rd/other", false}, {"/cargo/repo/crates/serde/1.0.0", false},
		{"/swift/repo/scope/package", true}, {"/swift/repo/scope/package/1.0.0.json", true},
		{"/swift/repo/scope/package/1.0.0.zip", false}, {"/swift/repo/scope/package/1.0.0", false},
		{"/swift/repo/scope/package/1.0.0/Package.swift", false}, {"/swift/repo/login", false},
		{"/nuget/repo/v3/index.json", false}, {"/maven/repo/maven-metadata.xml", false},
	} {
		for _, host := range []string{"origin.example.com", "vpce-test.codeartifact.repositories.us-east-1.vpce.amazonaws.com", "vpce-test.codeartifact.repositories.cn-north-1.vpce.amazonaws.com.cn"} {
			t.Run(host+tt.path, func(t *testing.T) {
				path := tt.path
				if strings.Contains(host, "vpce") {
					parts := strings.SplitN(path, "/", 3)
					path = "/" + parts[1] + "/d/domain-123456789012/" + parts[2]
				}
				origin, err := url.Parse("https://" + host + path)
				assert.NoError(t, err)
				route, ok := classifyMetadataRoute(*origin)
				assert.Equal(t, tt.valid, ok)
				if ok {
					assert.Equal(t, "repo", route.repository)
				}
			})
		}
	}
}
