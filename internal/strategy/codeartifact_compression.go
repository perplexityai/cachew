package strategy

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/alecthomas/errors"
)

func decodeCodeArtifactMetadata(resp *http.Response, headers http.Header, method string) error {
	switch strings.ToLower(strings.TrimSpace(strings.Join(headers.Values("Content-Encoding"), ","))) {
	case "", "identity":
		return nil
	case "gzip":
		if method != http.MethodHead && resp.StatusCode != http.StatusNotModified && resp.StatusCode != http.StatusNoContent {
			reader, err := gzip.NewReader(resp.Body)
			if err != nil {
				return errors.Wrap(err, "decode CodeArtifact metadata gzip")
			}
			resp.Body = &codeArtifactGzipBody{Reader: reader, origin: resp.Body}
		}
		resp.ContentLength = -1
		for _, name := range []string{"Content-Encoding", "Content-Length", "Content-MD5", "Digest", "ETag"} {
			headers.Del(name)
		}
		return nil
	default:
		return errors.New("unsupported CodeArtifact metadata encoding")
	}
}

type codeArtifactGzipBody struct {
	*gzip.Reader
	origin io.Closer
}

func (b *codeArtifactGzipBody) Close() error {
	return errors.Join(b.Reader.Close(), b.origin.Close())
}

func compressCodeArtifactMetadata(body []byte) ([]byte, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(body); err != nil {
		return nil, errors.Wrap(err, "compress CodeArtifact metadata")
	}
	if err := writer.Close(); err != nil {
		return nil, errors.Wrap(err, "finish compressed CodeArtifact metadata")
	}
	return compressed.Bytes(), nil
}

func codeArtifactGzipAccepted(headers http.Header) bool {
	gzipQuality, wildcardQuality, identityQuality := -1.0, -1.0, 0.0
	for _, value := range headers.Values("Accept-Encoding") {
		for entry := range strings.SplitSeq(value, ",") {
			coding, _, _ := strings.Cut(strings.TrimSpace(entry), ";")
			quality := codeArtifactEncodingQuality(entry)
			switch strings.ToLower(strings.TrimSpace(coding)) {
			case "gzip":
				gzipQuality = quality
			case "*":
				wildcardQuality = quality
			case "identity":
				identityQuality = quality
			}
		}
	}
	if gzipQuality < 0 {
		gzipQuality = wildcardQuality
	}
	return gzipQuality > 0 && gzipQuality >= identityQuality
}

func codeArtifactEncodingQuality(entry string) float64 {
	_, parameters, err := mime.ParseMediaType(strings.TrimSpace(entry))
	if err != nil {
		return 0
	}
	value, present := parameters["q"]
	if !present {
		return 1
	}
	quality, err := strconv.ParseFloat(value, 64)
	if err != nil || !(quality >= 0 && quality <= 1) {
		return 0
	}
	return quality
}
