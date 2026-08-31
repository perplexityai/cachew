package strategy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/alecthomas/errors"
)

const (
	maxCodeArtifactMetadataBytes = 64 << 20
	codeArtifactCargoFormat      = "cargo"
	codeArtifactSwiftFormat      = "swift"
)

func shouldRewriteCodeArtifactMetadata(path string) bool {
	lowerPath := strings.ToLower(path)
	switch codeArtifactPackageFormat(lowerPath) {
	case codeArtifactCargoFormat:
		return strings.HasSuffix(lowerPath, "/config.json")
	case "npm":
		return !strings.Contains(lowerPath, "/-/") || !strings.HasSuffix(lowerPath, ".tgz")
	case "nuget":
		return !strings.HasSuffix(lowerPath, ".nupkg") && !strings.HasSuffix(lowerPath, ".snupkg")
	case codeArtifactSwiftFormat:
		return !strings.HasSuffix(lowerPath, ".zip")
	default:
		return false
	}
}

func codeArtifactPackageFormat(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func stripCodeArtifactMetadataRequestHeaders(headers http.Header) {
	for _, name := range []string{
		"Accept-Encoding",
		"If-Match",
		"If-Modified-Since",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
		"Range",
	} {
		headers.Del(name)
	}
}

func isCodeArtifactJSONResponse(path string, headers http.Header) bool {
	contentType := codeArtifactContentType(headers)
	if contentType == "application/json" || strings.HasSuffix(contentType, "+json") {
		return true
	}
	lowerPath := strings.ToLower(path)
	return contentType == "application/octet-stream" &&
		codeArtifactPackageFormat(lowerPath) == codeArtifactCargoFormat &&
		strings.HasSuffix(lowerPath, "/config.json")
}

func isCodeArtifactSwiftArchiveResponse(path string, headers http.Header) bool {
	if codeArtifactPackageFormat(path) != codeArtifactSwiftFormat {
		return false
	}
	contentType := codeArtifactContentType(headers)
	return contentType == "application/zip" || contentType == "application/octet-stream" || strings.HasSuffix(contentType, "+zip")
}

func codeArtifactContentType(headers http.Header) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(headers.Get("Content-Type"), ";", 2)[0]))
}

func (c *CodeArtifact) rewriteMetadataResponse(
	resp *http.Response,
	headers http.Header,
	method string,
	originPath string,
) (http.Header, error) {
	rewrittenHeaders := codeArtifactRewrittenMetadataHeaders(headers)
	if method == http.MethodHead {
		return rewrittenHeaders, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCodeArtifactMetadataBytes+1))
	if err != nil {
		return nil, errors.Wrap(err, "read CodeArtifact package metadata")
	}
	if len(body) > maxCodeArtifactMetadataBytes {
		return nil, errors.New("CodeArtifact package metadata exceeds size limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var metadata any
	if err := decoder.Decode(&metadata); err != nil {
		return nil, errors.Wrap(err, "decode CodeArtifact package metadata")
	}
	if err := ensureJSONDocumentComplete(decoder); err != nil {
		return nil, err
	}

	c.rewriteMetadataURLs(metadata)
	if codeArtifactPackageFormat(originPath) == codeArtifactCargoFormat {
		if object, ok := metadata.(map[string]any); ok {
			object["auth-required"] = false
		}
	}
	rewrittenBody, err := json.Marshal(metadata)
	if err != nil {
		return nil, errors.Wrap(err, "encode CodeArtifact package metadata")
	}
	if err := resp.Body.Close(); err != nil {
		return nil, errors.Wrap(err, "close CodeArtifact package metadata")
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewrittenBody))
	rewrittenHeaders.Set("Content-Length", strconv.Itoa(len(rewrittenBody)))
	if rewrittenHeaders.Get("Content-Type") == "" {
		rewrittenHeaders.Set("Content-Type", "application/json")
	}
	return rewrittenHeaders, nil
}

func ensureJSONDocumentComplete(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "decode trailing CodeArtifact package metadata")
	}
	return errors.New("CodeArtifact package metadata contains multiple JSON values")
}

func codeArtifactRewrittenMetadataHeaders(headers http.Header) http.Header {
	rewritten := headers.Clone()
	for _, name := range []string{
		"Accept-Ranges",
		"Content-Encoding",
		"Content-Length",
		"Content-MD5",
		"Content-Range",
		"Digest",
		"ETag",
		"Last-Modified",
	} {
		rewritten.Del(name)
	}
	return rewritten
}

func (c *CodeArtifact) rewriteMetadataURLs(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if stringValue, ok := child.(string); ok {
				value[key] = c.rewriteMetadataURL(stringValue)
				continue
			}
			c.rewriteMetadataURLs(child)
		}
	case []any:
		for index, child := range value {
			if stringValue, ok := child.(string); ok {
				value[index] = c.rewriteMetadataURL(stringValue)
				continue
			}
			c.rewriteMetadataURLs(child)
		}
	}
}

func (c *CodeArtifact) rewriteMetadataURL(value string) string {
	target := c.target.String()
	if !strings.HasPrefix(value, target) {
		return value
	}
	suffix := strings.TrimPrefix(value, target)
	if suffix != "" && !strings.HasPrefix(suffix, "/") && !strings.HasPrefix(suffix, "?") && !strings.HasPrefix(suffix, "#") {
		return value
	}
	return c.proxyBase.String() + c.prefix + suffix
}
