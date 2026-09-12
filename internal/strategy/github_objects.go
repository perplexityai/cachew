package strategy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"golang.org/x/sync/errgroup"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
)

const (
	githubObjectsDefaultTarget     = "https://api.github.com/graphql"
	githubObjectsMaxRequestPaths   = 1000
	githubObjectsGraphQLBatchSize  = 200
	githubObjectsGraphQLConcurrent = 4
	githubObjectsCacheConcurrent   = 64
	githubObjectsMaxBodyBytes      = 4 * 1024 * 1024
	githubObjectsMaxPathBytes      = 4096
	githubObjectsUpstreamTimeout   = 15 * time.Second
	githubObjectsResponseError     = "response_error"
)

// GitHubObjectsConfig configures immutable GitHub object discovery.
type GitHubObjectsConfig struct {
	Target string `hcl:"target,optional" help:"GitHub GraphQL endpoint." default:"https://api.github.com/graphql"`
}

// GitHubObjects resolves immutable repository paths through batched GitHub GraphQL requests.
type GitHubObjects struct {
	target  string
	cache   cache.Cache
	client  *http.Client
	metrics *githubObjectsMetrics
}

type githubObjectsRequest struct {
	TreeSHA string   `json:"tree_sha"`
	Paths   []string `json:"paths"`
}

type githubObject struct {
	Path string  `json:"path"`
	OID  *string `json:"oid"`
}

type githubObjectsResponse struct {
	Objects []githubObject `json:"objects"`
}

type githubObjectsBatchResult struct {
	header http.Header
	err    error
}

type cachedGitHubObject struct {
	OID *string `json:"oid"`
}

type githubGraphQLRequest struct {
	Query     string            `json:"query"`
	Variables map[string]string `json:"variables"`
}

type githubGraphQLObject struct {
	TypeName string `json:"__typename"`
	OID      string `json:"oid"`
}

type githubGraphQLError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

type githubGraphQLResponse struct {
	Data struct {
		Repository map[string]*githubGraphQLObject `json:"repository"`
	} `json:"data"`
	Errors []githubGraphQLError `json:"errors"`
}

func RegisterGitHubObjects(r *Registry) {
	Register(r, "github-objects", "Caches exact immutable GitHub object lookups.", NewGitHubObjects)
}

// NewGitHubObjects creates a GitHub immutable-object lookup strategy.
func NewGitHubObjects(_ context.Context, config GitHubObjectsConfig, objectCache cache.Cache, mux Mux) (*GitHubObjects, error) {
	target := config.Target
	if target == "" {
		target = githubObjectsDefaultTarget
	}
	strategy := &GitHubObjects{
		target:  target,
		cache:   objectCache,
		client:  &http.Client{Timeout: githubObjectsUpstreamTimeout},
		metrics: newGitHubObjectsMetrics(),
	}
	mux.Handle("POST /api.github.com/repos/{owner}/{repo}/git/objects:batch", http.HandlerFunc(strategy.handle))
	return strategy, nil
}

var _ Strategy = (*GitHubObjects)(nil)

func (g *GitHubObjects) String() string { return "github-objects" }

func (g *GitHubObjects) handle(w http.ResponseWriter, r *http.Request) {
	response, header, err := g.resolve(r)
	if err != nil {
		if responder, ok := errors.AsType[httputil.HTTPResponder](err); ok {
			responder.WriteHTTP(w, r)
			return
		}
		httputil.ErrorResponse(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	copyGitHubRateLimitHeaders(w.Header(), header)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		httputil.ErrorResponse(w, r, http.StatusInternalServerError, "encode GitHub objects response")
	}
}

func (g *GitHubObjects) resolve(r *http.Request) (githubObjectsResponse, http.Header, error) {
	request, err := decodeGitHubObjectsRequest(r)
	if err != nil {
		return githubObjectsResponse{}, nil, httputil.Errorf(http.StatusBadRequest, "%s", err)
	}
	if err := validateGitHubObjectsRequest(request); err != nil {
		return githubObjectsResponse{}, nil, httputil.Errorf(http.StatusBadRequest, "%s", err)
	}
	g.metrics.recordRequest(r.Context(), len(request.Paths))

	objects := make([]githubObject, len(request.Paths))
	hits := make([]bool, len(request.Paths))
	misses := make([]int, 0, len(request.Paths))
	var cacheGroup errgroup.Group
	cacheGroup.SetLimit(githubObjectsCacheConcurrent)
	for index, objectPath := range request.Paths {
		cacheGroup.Go(func() error {
			cached, found, err := g.loadCached(r.Context(), r.PathValue("owner"), r.PathValue("repo"), request.TreeSHA, objectPath)
			if err != nil {
				return err
			}
			g.metrics.recordCacheLookup(r.Context(), found)
			objects[index] = githubObject{Path: objectPath}
			if found {
				objects[index].OID = cached.OID
				hits[index] = true
				return nil
			}
			return nil
		})
	}
	if err := cacheGroup.Wait(); err != nil {
		return githubObjectsResponse{}, nil, httputil.Errorf(http.StatusInternalServerError, "read cached GitHub object: %v", err)
	}
	for index := range objects {
		if hits[index] {
			continue
		}
		misses = append(misses, index)
	}

	header, err := g.fetchMisses(r, request, objects, misses)
	if err != nil {
		return githubObjectsResponse{}, nil, err
	}
	return githubObjectsResponse{Objects: objects}, header, nil
}

func decodeGitHubObjectsRequest(r *http.Request) (githubObjectsRequest, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, githubObjectsMaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request githubObjectsRequest
	if err := decoder.Decode(&request); err != nil {
		return githubObjectsRequest{}, errors.Wrap(err, "decode request")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return githubObjectsRequest{}, errors.New("request must contain one JSON object")
	}
	return request, nil
}

func validateGitHubObjectsRequest(request githubObjectsRequest) error {
	if !isGitHubOID(request.TreeSHA) {
		return errors.New("tree_sha must be a 40-character hexadecimal object ID")
	}
	if len(request.Paths) == 0 || len(request.Paths) > githubObjectsMaxRequestPaths {
		return errors.Errorf("paths must contain between 1 and %d entries", githubObjectsMaxRequestPaths)
	}
	seen := make(map[string]struct{}, len(request.Paths))
	for _, objectPath := range request.Paths {
		parts := strings.Split(objectPath, "/")
		if objectPath == "" || len(objectPath) > githubObjectsMaxPathBytes || objectPath == "." || strings.HasPrefix(objectPath, "/") || strings.ContainsAny(objectPath, "\\\x00") || path.Clean(objectPath) != objectPath || slices.Contains(parts, "..") {
			return errors.Errorf("path %q must be repository-relative", objectPath)
		}
		if _, exists := seen[objectPath]; exists {
			return errors.Errorf("path %q is duplicated", objectPath)
		}
		seen[objectPath] = struct{}{}
	}
	return nil
}

func isGitHubOID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func (g *GitHubObjects) fetchMisses(r *http.Request, request githubObjectsRequest, objects []githubObject, misses []int) (http.Header, error) {
	if len(misses) == 0 {
		return http.Header{}, nil
	}
	var group errgroup.Group
	group.SetLimit(githubObjectsGraphQLConcurrent)
	results := make([]githubObjectsBatchResult, (len(misses)+githubObjectsGraphQLBatchSize-1)/githubObjectsGraphQLBatchSize)
	for start := 0; start < len(misses); start += githubObjectsGraphQLBatchSize {
		end := min(start+githubObjectsGraphQLBatchSize, len(misses))
		batch := misses[start:end]
		batchIndex := start / githubObjectsGraphQLBatchSize
		group.Go(func() error {
			header, err := g.fetchBatch(r, request, objects, batch)
			results[batchIndex] = githubObjectsBatchResult{header: header, err: err}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, errors.WithStack(err)
	}
	header := aggregateGitHubRateLimitHeaders(results)
	if err := selectGitHubObjectsBatchError(results, header); err != nil {
		return nil, err
	}
	return header, nil
}

func (g *GitHubObjects) fetchBatch(r *http.Request, request githubObjectsRequest, objects []githubObject, indices []int) (http.Header, error) {
	startedAt := time.Now()
	result := "success"
	defer func() { g.metrics.recordOrigin(context.WithoutCancel(r.Context()), result, startedAt) }()
	body := buildGitHubObjectsGraphQL(r.PathValue("owner"), r.PathValue("repo"), request.TreeSHA, request.Paths, indices)
	encoded, err := json.Marshal(body)
	if err != nil {
		result = "request_error"
		return nil, errors.Wrap(err, "encode GitHub GraphQL request")
	}
	upstream, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.target, bytes.NewReader(encoded))
	if err != nil {
		result = "request_error"
		return nil, errors.Wrap(err, "create GitHub GraphQL request")
	}
	upstream.Header.Set("Accept", "application/vnd.github+json")
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("X-Github-Api-Version", "2022-11-28")
	upstream.Header.Set("Authorization", r.Header.Get("Authorization"))
	response, err := g.client.Do(upstream)
	if err != nil {
		result = "transport_error"
		return nil, httputil.Errorf(http.StatusBadGateway, "GitHub GraphQL request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result = fmt.Sprintf("http_%d", response.StatusCode)
		return response.Header.Clone(), githubObjectsUpstreamError{
			status:     response.StatusCode,
			statusText: response.Status,
			header:     response.Header,
		}
	}
	var payload githubGraphQLResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, githubObjectsMaxBodyBytes)).Decode(&payload); err != nil {
		result = githubObjectsResponseError
		return nil, httputil.Errorf(http.StatusBadGateway, "decode GitHub GraphQL response: %v", err)
	}
	if len(payload.Errors) > 0 {
		result = "graphql_error"
		return response.Header.Clone(), githubObjectsUpstreamError{
			status:     graphQLErrorStatus(payload.Errors),
			statusText: "GraphQL errors",
			header:     response.Header,
		}
	}
	if payload.Data.Repository == nil {
		result = githubObjectsResponseError
		return nil, httputil.Errorf(http.StatusBadGateway, "GitHub GraphQL returned no repository")
	}

	fetched, err := parseGitHubGraphQLObjects(payload.Data.Repository, request.TreeSHA, request.Paths, indices)
	if err != nil {
		result = githubObjectsResponseError
		return nil, err
	}
	if err := g.cacheFetchedObjects(r, request.TreeSHA, fetched); err != nil {
		return nil, err
	}
	for aliasIndex, objectIndex := range indices {
		objects[objectIndex] = fetched[aliasIndex]
	}
	return response.Header.Clone(), nil
}

func aggregateGitHubRateLimitHeaders(results []githubObjectsBatchResult) http.Header {
	selected := http.Header{}
	remaining := int(^uint(0) >> 1)
	reset := int64(0)
	retryAt := time.Time{}
	retryAfter := ""
	now := time.Now()
	for _, result := range results {
		header := result.header
		if len(selected) == 0 && len(header) > 0 {
			selected = header.Clone()
		}
		value, err := strconv.Atoi(header.Get("X-Ratelimit-Remaining"))
		if err == nil && value < remaining {
			selected = header.Clone()
			remaining = value
		}
		if value, err := strconv.ParseInt(header.Get("X-Ratelimit-Reset"), 10, 64); err == nil && value > reset {
			reset = value
		}
		if candidate, ok := retryAfterTime(header.Get("Retry-After"), now); ok && candidate.After(retryAt) {
			retryAt = candidate
			retryAfter = header.Get("Retry-After")
		}
	}
	if retryAfter != "" {
		selected.Set("Retry-After", retryAfter)
	}
	if reset > 0 {
		selected.Set("X-Ratelimit-Reset", strconv.FormatInt(reset, 10))
	}
	return selected
}

func retryAfterTime(value string, now time.Time) (time.Time, bool) {
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	retryAt, err := http.ParseTime(value)
	return retryAt, err == nil
}

func selectGitHubObjectsBatchError(results []githubObjectsBatchResult, header http.Header) error {
	var firstError error
	for _, result := range results {
		if result.err == nil {
			continue
		}
		if firstError == nil {
			firstError = result.err
		}
		upstreamError, ok := errors.AsType[githubObjectsUpstreamError](result.err)
		if ok && upstreamError.status == http.StatusTooManyRequests {
			upstreamError.header = header
			return upstreamError
		}
	}
	if firstError == nil {
		return nil
	}
	return errors.WithStack(firstError)
}

func copyGitHubRateLimitHeaders(target, source http.Header) {
	for _, name := range []string{
		"Retry-After",
		"X-Ratelimit-Limit",
		"X-Ratelimit-Remaining",
		"X-Ratelimit-Reset",
		"X-Ratelimit-Resource",
	} {
		if value := source.Get(name); value != "" {
			target.Set(name, value)
		}
	}
}

type githubObjectsUpstreamError struct {
	status     int
	statusText string
	header     http.Header
}

func (e githubObjectsUpstreamError) Error() string {
	return fmt.Sprintf("GitHub GraphQL returned %s", e.statusText)
}

func (e githubObjectsUpstreamError) WriteHTTP(w http.ResponseWriter, r *http.Request) {
	copyGitHubRateLimitHeaders(w.Header(), e.header)
	httputil.ErrorResponse(w, r, e.status, e.Error())
}

func parseGitHubGraphQLObjects(repository map[string]*githubGraphQLObject, treeSHA string, paths []string, indices []int) ([]githubObject, error) {
	root, rootExists := repository["root"]
	if !rootExists || root == nil || root.TypeName != "Tree" || !strings.EqualFold(root.OID, treeSHA) {
		return nil, httputil.Errorf(http.StatusBadGateway, "GitHub GraphQL did not resolve the requested tree")
	}
	fetched := make([]githubObject, len(indices))
	for aliasIndex, objectIndex := range indices {
		alias := fmt.Sprintf("o%d", aliasIndex)
		object, exists := repository[alias]
		if !exists {
			return nil, httputil.Errorf(http.StatusBadGateway, "GitHub GraphQL omitted object %s", alias)
		}
		if object == nil {
			fetched[aliasIndex] = githubObject{Path: paths[objectIndex]}
			continue
		}
		if object.TypeName == "Blob" && isGitHubOID(object.OID) {
			oid := object.OID
			fetched[aliasIndex] = githubObject{Path: paths[objectIndex], OID: &oid}
			continue
		}
		if object.TypeName == "Blob" {
			return nil, httputil.Errorf(http.StatusBadGateway, "GitHub GraphQL returned an invalid blob object ID")
		}
		switch object.TypeName {
		case "Commit", "Tag", "Tree":
			fetched[aliasIndex] = githubObject{Path: paths[objectIndex]}
		default:
			return nil, httputil.Errorf(http.StatusBadGateway, "GitHub GraphQL returned an invalid object type")
		}
	}
	return fetched, nil
}

func (g *GitHubObjects) cacheFetchedObjects(r *http.Request, treeSHA string, fetched []githubObject) error {
	var cacheGroup errgroup.Group
	cacheGroup.SetLimit(githubObjectsCacheConcurrent)
	for aliasIndex := range fetched {
		cacheGroup.Go(func() error {
			return g.storeCached(r.Context(), r.PathValue("owner"), r.PathValue("repo"), treeSHA, fetched[aliasIndex])
		})
	}
	if err := cacheGroup.Wait(); err != nil {
		return httputil.Errorf(http.StatusInternalServerError, "cache GitHub object: %v", err)
	}
	return nil
}

func buildGitHubObjectsGraphQL(owner, repo, treeSHA string, paths []string, indices []int) githubGraphQLRequest {
	variables := map[string]string{"owner": owner, "repo": repo, "tree": treeSHA}
	definitions := []string{"$owner:String!", "$repo:String!", "$tree:GitObjectID!"}
	fields := make([]string, 0, len(indices)+1)
	fields = append(fields, "root:object(oid:$tree){__typename oid}")
	for aliasIndex, objectIndex := range indices {
		variable := fmt.Sprintf("expr%d", aliasIndex)
		definitions = append(definitions, "$"+variable+":String!")
		fields = append(fields, fmt.Sprintf("o%d:object(expression:$%s){__typename ... on Blob{oid}}", aliasIndex, variable))
		variables[variable] = treeSHA + ":" + paths[objectIndex]
	}
	return githubGraphQLRequest{
		Query:     "query(" + strings.Join(definitions, ",") + "){repository(owner:$owner,name:$repo){" + strings.Join(fields, " ") + "}}",
		Variables: variables,
	}
}

func graphQLErrorStatus(graphQLErrors []githubGraphQLError) int {
	for _, graphQLError := range graphQLErrors {
		switch graphQLError.Type {
		case "RATE_LIMITED":
			return http.StatusTooManyRequests
		case "FORBIDDEN":
			return http.StatusForbidden
		}
	}
	return http.StatusBadGateway
}

func (g *GitHubObjects) loadCached(ctx context.Context, owner, repo, treeSHA, objectPath string) (cachedGitHubObject, bool, error) {
	reader, _, err := g.cache.Open(ctx, githubObjectCacheKey(owner, repo, treeSHA, objectPath))
	if errors.Is(err, os.ErrNotExist) {
		return cachedGitHubObject{}, false, nil
	}
	if err != nil {
		return cachedGitHubObject{}, false, errors.WithStack(err)
	}
	defer reader.Close()
	var object cachedGitHubObject
	if err := json.NewDecoder(io.LimitReader(reader, 1024)).Decode(&object); err != nil {
		return cachedGitHubObject{}, false, errors.Wrap(err, "decode cached object")
	}
	return object, true, nil
}

func (g *GitHubObjects) storeCached(ctx context.Context, owner, repo, treeSHA string, object githubObject) error {
	writer, err := g.cache.Create(ctx, githubObjectCacheKey(owner, repo, treeSHA, object.Path), http.Header{"Content-Type": {"application/json"}}, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := json.NewEncoder(writer).Encode(cachedGitHubObject{OID: object.OID}); err != nil {
		return errors.Join(err, writer.Abort(err))
	}
	return errors.WithStack(writer.Close())
}

func githubObjectCacheKey(owner, repo, treeSHA, objectPath string) cache.Key {
	return cache.NewKey("github-object\n" + owner + "/" + repo + "\n" + treeSHA + "\n" + objectPath)
}
