package strategy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"github.com/minio/minio-go/v7"
	"github.com/zeebo/blake3"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/s3client"
)

const releaseVerifiedHeader = "X-Cachew-Release-Verified"

var releaseSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ReleaseArtifactsConfig pins the origin and admission scope independently of request headers.
type ReleaseArtifactsConfig struct {
	Bucket             string        `hcl:"bucket"`
	Prefix             string        `hcl:"prefix,optional" default:"published"`
	Artifacts          []string      `hcl:"artifacts"`
	Classes            []string      `hcl:"classes"`
	MaxBlobBytes       int64         `hcl:"max-blob-bytes,optional" default:"1073741824"`
	MaxConcurrentFills int           `hcl:"max-concurrent-fills,optional" default:"4"`
	FetchTimeout       time.Duration `hcl:"fetch-timeout,optional" default:"2m"`
}

// ReleaseArtifacts serves immutable completed blobs without exposing an S3 URL.
type ReleaseArtifacts struct {
	config ReleaseArtifactsConfig
	source *minio.Client
	cache  cache.Cache
	fills  chan struct{}
}

type releaseBlob struct{ artifact, class, algorithm, digest string }
type releaseCompletion struct {
	SchemaVersion int    `json:"schema_version"`
	Artifact      string `json:"artifact"`
	Class         string `json:"class"`
	Hash          string `json:"hash"`
	Digest        string `json:"digest"`
	Size          int64  `json:"size"`
	Ready         bool   `json:"ready"`
}

// RegisterReleaseArtifacts makes verified S3 delivery opt-in through configuration.
func RegisterReleaseArtifacts(r *Registry, provider s3client.ClientProvider) {
	Register(r, "release-artifacts", "Serves completed, digest-verified S3 artifacts.", func(ctx context.Context, cfg ReleaseArtifactsConfig, c cache.Cache, mux Mux) (*ReleaseArtifacts, error) {
		source, err := provider()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return NewReleaseArtifacts(ctx, cfg, source, c, mux)
	})
}

// NewReleaseArtifacts rejects ambiguous routes and unbounded origin fills at startup.
func NewReleaseArtifacts(_ context.Context, cfg ReleaseArtifactsConfig, source *minio.Client, c cache.Cache, mux Mux) (*ReleaseArtifacts, error) {
	if cfg.Prefix == "" {
		cfg.Prefix = "published"
	}
	if cfg.MaxBlobBytes == 0 {
		cfg.MaxBlobBytes = 1 << 30
	}
	if cfg.MaxConcurrentFills == 0 {
		cfg.MaxConcurrentFills = 4
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 2 * time.Minute
	}
	if source == nil || cfg.Bucket == "" || !validReleaseName(cfg.Prefix, false) || len(cfg.Classes) == 0 || len(cfg.Artifacts) == 0 || cfg.MaxBlobBytes < 1 || cfg.MaxBlobBytes > 1<<40 || cfg.MaxConcurrentFills < 1 || cfg.FetchTimeout < time.Second {
		return nil, errors.Errorf("invalid release-artifacts origin or limits")
	}
	for _, artifact := range cfg.Artifacts {
		if !validReleaseName(artifact, true) {
			return nil, errors.Errorf("invalid release-artifacts registration")
		}
	}
	for _, class := range cfg.Classes {
		if !slices.Contains([]string{"releases", "builds", "previews"}, class) {
			return nil, errors.Errorf("invalid release-artifacts class")
		}
	}
	s := &ReleaseArtifacts{config: cfg, source: source, cache: c.Namespace("release-artifacts"), fills: make(chan struct{}, cfg.MaxConcurrentFills)}
	mux.Handle("GET /artifacts/", s)
	return s, nil
}

func validReleaseName(name string, artifact bool) bool {
	parts := strings.Split(name, "/")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if !releaseSegment.MatchString(p) || artifact && slices.Contains([]string{"builds", "previews", "releases", "records", "channels", "blob"}, p) {
			return false
		}
	}
	return true
}

// String identifies the strategy without disclosing its source bucket.
func (*ReleaseArtifacts) String() string { return "release-artifacts" }

func (s *ReleaseArtifacts) parse(r *http.Request) (releaseBlob, bool) {
	b := releaseBlob{class: "releases"}
	if r.Method != http.MethodGet && r.Method != http.MethodHead || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		return b, false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/artifacts/"), "/")
	n := len(parts)
	if n < 4 || parts[n-3] != "blob" {
		return b, false
	}
	b.algorithm, b.digest = parts[n-2], parts[n-1]
	name := parts[:n-3]
	if len(name) > 1 && slices.Contains([]string{"builds", "previews"}, name[len(name)-1]) {
		b.class = name[len(name)-1]
		name = name[:len(name)-1]
	}
	b.artifact = strings.Join(name, "/")
	h := releaseHash(b.algorithm)
	digest, err := hex.DecodeString(b.digest)
	return b, h != nil && err == nil && len(digest) == h.Size() && b.digest == strings.ToLower(b.digest) && slices.Contains(s.config.Artifacts, b.artifact) && slices.Contains(s.config.Classes, b.class)
}

func releaseHash(algorithm string) hash.Hash {
	switch algorithm {
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	case "blake3":
		return blake3.New()
	default:
		return nil
	}
}
func (s *ReleaseArtifacts) root(b releaseBlob) string {
	return s.config.Prefix + "/" + b.class + "/" + b.artifact + "/blobs/" + b.algorithm + "/" + b.digest + "/"
}
func (s *ReleaseArtifacts) key(b releaseBlob) cache.Key {
	return cache.NewKey("verified-release-v1:" + s.source.EndpointURL().String() + "/" + s.config.Bucket + "/" + s.root(b))
}
func releaseETag(b releaseBlob) string { return `"` + b.algorithm + ":" + b.digest + `"` }

// ServeHTTP checks deployment admission before consulting any cached representation.
func (s *ReleaseArtifacts) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, ok := s.parse(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if s.serveCached(w, r, b) {
		return
	}
	select {
	case s.fills <- struct{}{}:
		defer func() { <-s.fills }()
	default:
		http.Error(w, "artifact fill capacity exhausted", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.FetchTimeout)
	defer cancel()
	completion, err := s.completion(ctx, b)
	if err != nil {
		s.fail(w, err)
		return
	}
	headers := http.Header{"Content-Type": {"application/octet-stream"}, "Content-Length": {strconv.FormatInt(completion.Size, 10)}, "Etag": {releaseETag(b)}, "Cache-Control": {"private, no-store"}, releaseVerifiedHeader: {"1"}}
	if r.Method == http.MethodHead {
		info, err := s.source.StatObject(ctx, s.config.Bucket, s.root(b)+"payload", minio.StatObjectOptions{})
		if err != nil || info.Size != completion.Size {
			s.fail(w, errors.New("artifact metadata unavailable"))
			return
		}
		s.serveHead(w, r, headers)
		return
	}
	file, err := s.download(ctx, b, completion.Size)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer removeReleaseFile(file)
	// Only a fully verified file may commit a cache entry. Never stream an
	// unverified prefix to either a client or a cache that readers can observe.
	if err := s.store(ctx, b, headers, file); err != nil {
		logging.FromContext(ctx).WarnContext(ctx, "release artifact cache write failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		s.fail(w, err)
		return
	}
	headers.Del(releaseVerifiedHeader)
	maps.Copy(w.Header(), headers)
	http.ServeContent(w, r, "payload", time.Time{}, file)
}

func (s *ReleaseArtifacts) fail(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if response, ok := errors.AsType[minio.ErrorResponse](err); ok && response.Code == "NoSuchKey" {
		status = http.StatusNotFound
	}
	http.Error(w, "artifact unavailable", status)
}

func (s *ReleaseArtifacts) serveHead(w http.ResponseWriter, r *http.Request, h http.Header) {
	h = maps.Clone(h)
	h.Del(releaseVerifiedHeader)
	maps.Copy(w.Header(), h)
	if status := httputil.CheckConditionals(r, h.Get("ETag")); status != 0 {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
}

func (s *ReleaseArtifacts) serveCached(w http.ResponseWriter, r *http.Request, b releaseBlob) bool {
	h, err := s.cache.Stat(r.Context(), s.key(b))
	size, sizeErr := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	if err != nil || h.Get(releaseVerifiedHeader) != "1" || h.Get("ETag") != releaseETag(b) || sizeErr != nil || size < 0 || size > s.config.MaxBlobBytes {
		return false
	}
	if r.Method == http.MethodHead {
		s.serveHead(w, r, h)
		return true
	}
	body, headers, err := s.cache.Open(r.Context(), s.key(b), httputil.ConditionalOptions(r)...)
	if err == nil && (headers.Get(releaseVerifiedHeader) != "1" || headers.Get("ETag") != releaseETag(b)) {
		_ = body.Close()
		return false
	}
	headers = maps.Clone(headers)
	headers.Del(releaseVerifiedHeader)
	handled, _, serveErr := httputil.ServeCacheHit(w, headers, body, err)
	if serveErr != nil {
		logging.FromContext(r.Context()).WarnContext(r.Context(), "release artifact response interrupted")
	}
	return handled
}

func (s *ReleaseArtifacts) completion(ctx context.Context, b releaseBlob) (releaseCompletion, error) {
	var c releaseCompletion
	object, err := s.source.GetObject(ctx, s.config.Bucket, s.root(b)+"complete.json", minio.GetObjectOptions{})
	if err != nil {
		return c, errors.WithStack(err)
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, 65537))
	if err != nil {
		return c, errors.WithStack(err)
	}
	if len(data) > 65536 {
		return c, errors.New("completion too large")
	}
	// Duplicate fields must not let the publisher and byte server interpret
	// different readiness decisions for the same completion object.
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return c, errors.New("invalid completion")
	}
	seen := map[string]bool{}
	for dec.More() {
		fieldToken, err := dec.Token()
		if err != nil {
			return c, errors.WithStack(err)
		}
		key, ok := fieldToken.(string)
		if !ok || seen[key] {
			return c, errors.New("duplicate completion field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return c, errors.WithStack(err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return c, errors.WithStack(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return c, errors.New("trailing completion data")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, errors.WithStack(err)
	}
	if len(seen) != 7 || c.SchemaVersion != 1 || !c.Ready || c.Artifact != b.artifact || c.Class != b.class || c.Hash != b.algorithm || c.Digest != b.digest || c.Size < 0 || c.Size > s.config.MaxBlobBytes {
		return c, errors.New("invalid completion")
	}
	return c, nil
}

func (s *ReleaseArtifacts) download(ctx context.Context, b releaseBlob, size int64) (*os.File, error) {
	object, err := s.source.GetObject(ctx, s.config.Bucket, s.root(b)+"payload", minio.GetObjectOptions{})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer object.Close()
	f, err := os.CreateTemp("", "cachew-release-*")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	h := releaseHash(b.algorithm)
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(object, size+1))
	if err == nil && (n != size || hex.EncodeToString(h.Sum(nil)) != b.digest) {
		err = errors.New("artifact integrity mismatch")
	}
	if err != nil {
		removeReleaseFile(f)
		return nil, errors.WithStack(err)
	}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		removeReleaseFile(f)
		return nil, errors.WithStack(err)
	}
	return f, nil
}

func (s *ReleaseArtifacts) store(ctx context.Context, b releaseBlob, h http.Header, f *os.File) error {
	writer, err := s.cache.Create(ctx, s.key(b), h, 0, cache.WithETag(b.algorithm+":"+b.digest))
	if err != nil {
		return errors.WithStack(err)
	}
	if _, err := io.Copy(writer, f); err != nil {
		return errors.WithStack(errors.Join(err, writer.Abort(err)))
	}
	return errors.WithStack(writer.Close())
}

func removeReleaseFile(file *os.File) {
	_ = file.Close()
	_ = os.Remove(file.Name()) //nolint:gosec // The name comes only from os.CreateTemp, never the request.
}
