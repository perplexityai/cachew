package packagepolicy

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/alecthomas/errors"
	"golang.org/x/mod/module"
)

var pypiNormalizationPattern = regexp.MustCompile(`[-_.]+`)

// npmFormat is the only CodeArtifact format whose clients percent-encode a slash inside a segment.
const npmFormat = "npm"

var (
	// ErrNotApplicable reports a path that is not an evaluated immutable package asset, such as
	// repository metadata or a format without a PURL mapping.
	ErrNotApplicable = errors.New("package policy: path is not an evaluated package asset")
	// ErrEncodedSeparator reports a percent-encoded slash inside a segment of an evaluated format.
	// Package clients never send one for an asset except npm's "@scope%2Fname" spelling, and the
	// origin may decode it into a different path than Cachew evaluated, so callers deny the request.
	ErrEncodedSeparator = errors.New("package policy: encoded path separator")
)

// PackageURLForCodeArtifact derives a PURL from the escaped path of an immutable npm, PyPI, Maven,
// or Cargo CodeArtifact asset. Segments are decoded individually so an encoded slash cannot change
// how the path is split.
func PackageURLForCodeArtifact(escapedPath string) (string, error) {
	parts, ok := decodedPathParts(escapedPath)
	if !ok {
		return "", ErrNotApplicable
	}
	format := strings.ToLower(parts[0])
	packageURL, evaluated := codeArtifactPackageURL(format)
	if !evaluated {
		return "", ErrNotApplicable
	}
	for _, part := range parts {
		if strings.Contains(part, "/") && (format != npmFormat || !npmScopedName(part)) {
			return "", ErrEncodedSeparator
		}
	}
	if format == npmFormat && len(parts) > 2 && npmScopedName(parts[2]) {
		parts = slices.Concat(parts[:2], strings.SplitN(parts[2], "/", 2), parts[3:])
	}
	if len(parts) < 5 {
		return "", ErrNotApplicable
	}
	purl, ok := packageURL(parts)
	if !ok {
		return "", ErrNotApplicable
	}
	return purl, nil
}

func codeArtifactPackageURL(format string) (func([]string) (string, bool), bool) {
	switch format {
	case npmFormat:
		return npmPackageURL, true
	case "pypi":
		return pypiPackageURL, true
	case "maven":
		return mavenPackageURL, true
	case "cargo":
		return cargoPackageURL, true
	default:
		return nil, false
	}
}

// npmScopedName reports whether a decoded segment is the "@scope/name" that npm clients send as
// "@scope%2Fname" for package metadata and, from some clients, tarballs.
func npmScopedName(segment string) bool {
	scope, name, ok := strings.Cut(segment, "/")
	return ok && len(scope) > 1 && strings.HasPrefix(scope, "@") &&
		name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
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

func mavenPackageURL(parts []string) (string, bool) {
	if len(parts) < 6 {
		return "", false
	}
	group, artifact, version, filename := parts[2:len(parts)-3], parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1]
	if strings.HasSuffix(version, "-SNAPSHOT") || !strings.HasPrefix(filename, artifact+"-"+version) {
		return "", false
	}
	return "pkg:maven/" + escapePURLSegment(strings.Join(group, ".")) + "/" + escapePURLSegment(artifact) + "@" + escapePURLSegment(version), true
}

func cargoPackageURL(parts []string) (string, bool) {
	if len(parts) != 5 || parts[2] != "crates" {
		return "", false
	}
	return "pkg:cargo/" + escapePURLSegment(parts[3]) + "@" + escapePURLSegment(parts[4]), true
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

// decodedPathParts splits the escaped path before decoding each segment so "%2F" stays inside its segment.
func decodedPathParts(escapedPath string) ([]string, bool) {
	parts := strings.Split(strings.Trim(escapedPath, "/"), "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" {
			return nil, false
		}
		parts[i] = decoded
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
