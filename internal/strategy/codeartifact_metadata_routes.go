package strategy

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var metadataRoutingSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var npmMetadataPackage = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*(?:/|%2[fF]))?[a-z0-9][a-z0-9._-]*$`)
var pypiMetadataProject = regexp.MustCompile(`^simple/[a-z0-9]+(?:-[a-z0-9]+)*/$`)
var cargoMetadataName = regexp.MustCompile(`^[a-z0-9_-]+$`)
var swiftMetadataVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\.json$`)

func metadataFormatClassifier(format string) func(string) bool {
	switch format {
	case codeArtifactNPMFormat:
		return npmMetadataPackage.MatchString
	case codeArtifactPyPIFormat:
		return pypiMetadataProject.MatchString
	case codeArtifactCargoFormat:
		return isCargoMetadataPath
	case codeArtifactSwiftFormat:
		return isSwiftMetadataPath
	default:
		return nil
	}
}

type metadataRoute struct {
	format     string
	repository string
}

func classifyMetadataRoute(origin url.URL) (metadataRoute, bool) {
	parts := strings.Split(strings.TrimPrefix(origin.EscapedPath(), "/"), "/")
	if len(parts) < 3 {
		return metadataRoute{}, false
	}
	classify := metadataFormatClassifier(parts[0])
	if classify == nil {
		return metadataRoute{}, false
	}
	repositoryIndex := 1
	host := strings.ToLower(origin.Hostname())
	if strings.HasSuffix(host, ".vpce.amazonaws.com") || strings.HasSuffix(host, ".vpce.amazonaws.com.cn") {
		if len(parts) < 5 || parts[1] != "d" || !metadataRoutingSegment.MatchString(parts[2]) {
			return metadataRoute{}, false
		}
		repositoryIndex = 3
	}
	repository := parts[repositoryIndex]
	if !metadataRoutingSegment.MatchString(repository) || !classify(strings.Join(parts[repositoryIndex+1:], "/")) {
		return metadataRoute{}, false
	}
	return metadataRoute{format: parts[0], repository: repository}, true
}

func isCargoMetadataPath(path string) bool {
	if path == "config.json" {
		return true
	}
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	if !cargoMetadataName.MatchString(name) {
		return false
	}
	switch len(name) {
	case 1:
		return path == "1/"+name
	case 2:
		return path == "2/"+name
	case 3:
		return path == "3/"+name[:1]+"/"+name
	default:
		return path == name[:2]+"/"+name[2:4]+"/"+name
	}
}

func isSwiftMetadataPath(path string) bool {
	parts := strings.Split(path, "/")
	if len(parts) != 2 && len(parts) != 3 {
		return false
	}
	if !metadataRoutingSegment.MatchString(parts[0]) || !metadataRoutingSegment.MatchString(parts[1]) {
		return false
	}
	return len(parts) == 2 || swiftMetadataVersion.MatchString(parts[2])
}

func (r metadataRoute) acceptsResponse(headers http.Header) bool {
	media := codeArtifactContentType(headers)
	switch r.format {
	case codeArtifactNPMFormat:
		return media == "application/json" || strings.HasSuffix(media, "+json")
	case codeArtifactPyPIFormat:
		return media == "text/html" || media == "application/vnd.pypi.simple.v1+html" || media == "application/vnd.pypi.simple.v1+json"
	case "cargo":
		return media == "application/json" || media == "application/octet-stream" || media == "text/plain"
	case "swift":
		return headers.Get("Content-Version") == "1" && (media == "application/json" || media == "application/vnd.swift.registry.v1+json")
	default:
		return false
	}
}
