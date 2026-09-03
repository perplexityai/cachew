package packagepolicy

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/module"
)

var pypiNormalizationPattern = regexp.MustCompile(`[-_.]+`)

// PackageURLForCodeArtifact derives a PURL from an immutable npm or PyPI CodeArtifact asset path.
func PackageURLForCodeArtifact(path string) (string, bool) {
	parts, ok := decodedPathParts(path)
	if !ok || len(parts) < 5 {
		return "", false
	}
	switch parts[0] {
	case "npm":
		return npmPackageURL(parts)
	case "pypi":
		return pypiPackageURL(parts)
	default:
		return "", false
	}
}

func npmPackageURL(parts []string) (string, bool) {
	var namespace, name, separator, filename string
	switch {
	case len(parts) == 5:
		name, separator, filename = parts[2], parts[3], parts[4]
	case len(parts) == 6 && strings.HasPrefix(parts[2], "@"):
		namespace, name, separator, filename = parts[2], parts[3], parts[4], parts[5]
	default:
		return "", false
	}
	if separator != "-" || !strings.HasSuffix(filename, ".tgz") {
		return "", false
	}
	version, ok := strings.CutPrefix(strings.TrimSuffix(filename, ".tgz"), name+"-")
	if !ok || version == "" || name == "" {
		return "", false
	}
	if namespace != "" {
		return "pkg:npm/" + escapePURLSegment(namespace) + "/" + escapePURLSegment(name) + "@" + escapePURLSegment(version), true
	}
	return "pkg:npm/" + escapePURLSegment(name) + "@" + escapePURLSegment(version), true
}

func pypiPackageURL(parts []string) (string, bool) {
	if len(parts) != 6 || parts[2] != "simple" || parts[3] == "" || parts[4] == "" || parts[5] == "" {
		return "", false
	}
	name := pypiNormalizationPattern.ReplaceAllString(strings.ToLower(parts[3]), "-")
	return "pkg:pypi/" + escapePURLSegment(name) + "@" + escapePURLSegment(parts[4]), true
}

// PackageURLForGoModule derives a PURL from a versioned Go module proxy path.
func PackageURLForGoModule(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/")
	modulePath, asset, ok := strings.Cut(path, "/@v/")
	if !ok || modulePath == "" {
		return "", false
	}
	var escapedVersion string
	for _, suffix := range []string{".info", ".mod", ".zip"} {
		if version, found := strings.CutSuffix(asset, suffix); found {
			escapedVersion = version
			break
		}
	}
	if escapedVersion == "" {
		return "", false
	}
	name, err := module.UnescapePath(modulePath)
	if err != nil {
		return "", false
	}
	version, err := module.UnescapeVersion(escapedVersion)
	if err != nil {
		return "", false
	}
	if module.Check(name, version) != nil || version != module.CanonicalVersion(version) {
		return "", false
	}
	return "pkg:golang/" + escapePURLPath(name) + "@" + escapePURLSegment(version), true
}

func decodedPathParts(path string) ([]string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if slices.Contains(parts, "") {
		return nil, false
	}
	return parts, true
}

func escapePURLPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = escapePURLSegment(part)
	}
	return strings.Join(parts, "/")
}

func escapePURLSegment(value string) string {
	escaped := url.PathEscape(value)
	return strings.ReplaceAll(escaped, "@", "%40")
}
