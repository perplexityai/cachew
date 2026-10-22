package strategy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type codeArtifactAssetOrigin struct {
	client *awscodeartifact.Client
	domain string
	owner  string
}

func (c *CodeArtifact) serveAsset(w http.ResponseWriter, r *http.Request, mode codeArtifactCacheMode) {
	origin := c.originURL(r)
	input, err := codeArtifactMavenAsset(origin.Path)
	if err != nil || origin.RawQuery != "" || origin.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	input.Domain, input.DomainOwner = aws.String(c.assets.domain), aws.String(c.assets.owner)
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	started := time.Now()
	output, err := c.assets.client.GetPackageVersionAsset(ctx, input)
	if err != nil {
		status := codeArtifactTransportStatus(ctx, err)
		var responseError *smithyhttp.ResponseError
		if errors.As(err, &responseError) {
			status = strconv.Itoa(responseError.HTTPStatusCode())
		}
		c.metric.recordOrigin(context.WithoutCancel(ctx), codeArtifactOriginObservation{
			status: status, format: "maven", duration: time.Since(started),
		})
		if responseError != nil {
			switch responseError.HTTPStatusCode() {
			case http.StatusNotFound, http.StatusForbidden, http.StatusTooManyRequests:
				http.Error(w, "CodeArtifact asset unavailable", responseError.HTTPStatusCode())
				return
			}
		}
		c.writeError(w, r, errors.Errorf("request CodeArtifact asset: %s", status))
		return
	}
	body := newCodeArtifactOriginBody(ctx, output.Asset, cancel, c.originReadIdleTimeout)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/octet-stream")
	headers.Set("Cache-Control", "public, immutable")
	if raw, ok := awsmiddleware.GetRawResponse(output.ResultMetadata).(*smithyhttp.Response); ok {
		if length := raw.Header.Get("Content-Length"); length != "" {
			headers.Set("Content-Length", length)
		}
	}
	if revision := aws.ToString(output.PackageVersionRevision); revision != "" {
		headers.Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(revision))))
	}
	resp := &http.Response{StatusCode: http.StatusOK, Header: headers, Body: body}
	c.observeOriginResponse(r.Context(), resp, origin.Path, started)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.ErrorContext(r.Context(), "Failed to close CodeArtifact asset", "error", err)
		}
	}()
	if status := cachedPreconditionStatus(r, headers); status != 0 {
		if status == http.StatusNotModified {
			copyHeaders(w.Header(), headers)
		}
		w.WriteHeader(status)
		return
	}
	copyHeaders(w.Header(), headers)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	// The asset API has no range operation. HTTP permits a complete 200 response
	// to Range; these reads stay uncached rather than storing a partial object.
	if mode == codeArtifactCacheLookup {
		c.streamAndCache(w, r, resp, headers)
	} else {
		c.streamOriginBody(r.Context(), w, resp.Body)
	}
}

func codeArtifactMavenAsset(path string) (*awscodeartifact.GetPackageVersionAssetInput, error) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	n := len(parts)
	if n < 6 || parts[0] != "maven" || strings.HasSuffix(parts[n-2], "-SNAPSHOT") {
		return nil, errors.New("expected a non-snapshot Maven asset path")
	}
	for _, part := range parts {
		if !aliasSegment.MatchString(part) || part == "." || part == ".." {
			return nil, errors.New("invalid Maven asset path segment")
		}
	}
	return &awscodeartifact.GetPackageVersionAssetInput{
		Repository: aws.String(parts[1]), Format: types.PackageFormatMaven,
		Namespace: aws.String(strings.Join(parts[2:n-3], ".")), Package: aws.String(parts[n-3]),
		PackageVersion: aws.String(parts[n-2]), Asset: aws.String(parts[n-1]),
	}, nil
}
