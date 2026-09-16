package packagepolicy

import (
	"net/url"
	"slices"
	"strings"

	"github.com/alecthomas/errors"
	"golang.org/x/mod/module"
)

var (
	// ErrNotApplicable reports a path that is not an evaluated immutable package asset, such as
	// repository metadata or a format without a PURL mapping.
	ErrNotApplicable = errors.New("package policy: path is not an evaluated package asset")
	// ErrEncodedSeparator reports a percent-encoded slash inside a segment of an evaluated format.
	// Package clients never send one for an asset except npm's "@scope%2Fname" spelling, and the
	// origin may decode it into a different path than Cachew evaluated, so callers deny the request.
	ErrEncodedSeparator = errors.New("package policy: encoded path separator")
	// ErrUnmappablePackage reports a recognized package body whose coordinate cannot be evaluated safely.
	ErrUnmappablePackage = errors.New("package policy: package body cannot be mapped to a PURL")
)

// PackageURLForCodeArtifact derives a PURL from an immutable npm asset URL.
// The origin distinguishes PrivateLink routing prefixes from ordinary repositories named "d".
// Segments are decoded individually so an encoded slash cannot change how the path is split.
func PackageURLForCodeArtifact(origin *url.URL) (string, error) {
	parts, ok := decodedPathParts(origin.EscapedPath())
	if !strings.EqualFold(parts[0], "npm") {
		return "", ErrNotApplicable
	}
	if !ok {
		return "", ErrUnmappablePackage
	}
	host := strings.ToLower(origin.Hostname())
	if strings.HasSuffix(host, ".vpce.amazonaws.com") || strings.HasSuffix(host, ".vpce.amazonaws.com.cn") {
		if len(parts) < 4 || parts[1] != "d" {
			return "", ErrUnmappablePackage
		}
		if strings.Contains(parts[2], "/") {
			return "", ErrEncodedSeparator
		}
		parts = slices.Concat(parts[:1], parts[3:])
	}
	for i, part := range parts {
		if strings.Contains(part, "/") && (i != 2 || !npmScopedName(part)) {
			return "", ErrEncodedSeparator
		}
	}
	if len(parts) > 2 && npmScopedName(parts[2]) {
		parts = slices.Concat(parts[:2], strings.SplitN(parts[2], "/", 2), parts[3:])
	}
	if purl, found := npmPackageURL(parts); found {
		return purl, nil
	}
	if len(parts) > 2 && slices.Contains(parts[2:], "-") && strings.HasSuffix(parts[len(parts)-1], ".tgz") {
		return "", ErrUnmappablePackage
	}
	return "", ErrNotApplicable
}

// npmScopedName reports whether a decoded package-name segment is the "@scope/name" that npm
// clients send as "@scope%2Fname" for package metadata and, from some clients, tarballs.
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
			return parts, false
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
	escaped := strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
	return strings.ReplaceAll(escaped, "%3A", ":")
}
