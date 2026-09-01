package strategy //nolint:testpackage // White-box coverage is required for token and transport injection.

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/packagepolicy"
)

const (
	testCodeArtifactDomain         = "example"
	testCodeArtifactDomainOwner    = "123456789012"
	testCodeArtifactRegion         = "us-east-1"
	testCodeArtifactRoleARN        = "arn:aws:iam::123456789012:role/cachew-reader"
	testCodeArtifactETag           = `"asset-v1"`
	testCodeArtifactMalformedETag  = "83522005c1266cc2de97e65072ff7554ac0f30ad369c3b02ff3a764b962048da"
	testCodeArtifactBody           = "immutable payload"
	testCodeArtifactCacheControl   = "public, max-age=3600, immutable"
	testCodeArtifactModified       = "Wed, 21 Oct 2015 07:28:00 GMT"
	testCodeArtifactBeforeModified = "Wed, 21 Oct 2015 07:27:59 GMT"
	testCodeArtifactFutureModified = "Wed, 21 Oct 2030 07:28:00 GMT"
)

type tokenResponse struct {
	token     string
	expiresAt time.Time
	status    int
}

type codeArtifactAuthorizationClientFunc func(
	context.Context,
	*awscodeartifact.GetAuthorizationTokenInput,
	...func(*awscodeartifact.Options),
) (*awscodeartifact.GetAuthorizationTokenOutput, error)

func (f codeArtifactAuthorizationClientFunc) GetAuthorizationToken(
	ctx context.Context,
	input *awscodeartifact.GetAuthorizationTokenInput,
	options ...func(*awscodeartifact.Options),
) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
	return f(ctx, input, options...)
}

type localTokenServer struct {
	server *httptest.Server

	mu        sync.Mutex
	responses []tokenResponse
	requests  int
	method    string
	path      string
	query     url.Values
}

func newLocalTokenServer(t *testing.T, responses ...tokenResponse) *localTokenServer {
	t.Helper()
	s := &localTokenServer{responses: responses}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		index := s.requests
		s.requests++
		s.method = r.Method
		s.path = r.URL.Path
		s.query = r.URL.Query()
		if index >= len(s.responses) {
			index = len(s.responses) - 1
		}
		response := s.responses[index]
		s.mu.Unlock()

		if response.status != 0 {
			http.Error(w, http.StatusText(response.status), response.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			w,
			`{"authorizationToken":%q,"expiration":%f}`,
			response.token,
			float64(response.expiresAt.Unix()),
		)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *localTokenServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *localTokenServer) tokenManager(now func() time.Time) *codeArtifactTokenManager {
	awsConfig := aws.Config{
		Credentials: credentials.NewStaticCredentialsProvider("access-key", "secret-key", "session-token"),
		HTTPClient:  s.server.Client(),
		Region:      testCodeArtifactRegion,
	}
	client := awscodeartifact.NewFromConfig(awsConfig, func(options *awscodeartifact.Options) {
		options.BaseEndpoint = aws.String(s.server.URL)
	})
	return newCodeArtifactTokenManagerWithClient(testCodeArtifactConfig("https://codeartifact.example.com"), client, now)
}

func testCodeArtifactConfig(target string) CodeArtifactConfig {
	return CodeArtifactConfig{
		Target:                target,
		ProxyBaseURL:          "https://cachew.example.com",
		Domain:                testCodeArtifactDomain,
		DomainOwner:           testCodeArtifactDomainOwner,
		Region:                testCodeArtifactRegion,
		RoleARN:               testCodeArtifactRoleARN,
		OriginHeaderTimeout:   defaultCodeArtifactOriginHeaderTimeout,
		OriginReadIdleTimeout: defaultCodeArtifactOriginReadIdleTimeout,
		CredentialTimeout:     defaultCodeArtifactCredentialTimeout,
	}
}

func newTestCodeArtifact(
	t *testing.T,
	origin http.Handler,
	responses ...tokenResponse,
) (*http.ServeMux, *httptest.Server, *localTokenServer, context.Context) {
	t.Helper()
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, responses...)

	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	mux := http.NewServeMux()
	_, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), cache.NoOpCache(), true)
	assert.NoError(t, err)
	return mux, originServer, tokenServer, ctx
}

func newTestCachingCodeArtifact(
	t *testing.T,
	origin http.Handler,
) (*http.ServeMux, *httptest.Server, *localTokenServer, *CodeArtifact, context.Context) {
	t.Helper()
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})

	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), memory, true)
	assert.NoError(t, err)
	return mux, originServer, tokenServer, strategy, ctx
}

func codeArtifactPath(origin *httptest.Server, suffix string) string {
	return "/" + origin.Listener.Addr().String() + suffix
}

func decodeBasicPassword(header string) (string, bool) {
	const prefix = "Basic "
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", false
	}
	username, password, ok := string(decoded), "", false
	if colon := len(codeArtifactUsername); len(username) > colon && username[:colon] == codeArtifactUsername && username[colon] == ':' {
		password, ok = username[colon+1:], true
	}
	return password, ok
}

type codeArtifactRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f codeArtifactRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type recordingPackagePolicy struct {
	decision      packagepolicy.Decision
	err           error
	purls         []string
	notApplicable int
}

func (r *recordingPackagePolicy) Evaluate(_ context.Context, purl string) (packagepolicy.Decision, error) {
	r.purls = append(r.purls, purl)
	return r.decision, r.err
}

func (r *recordingPackagePolicy) ObserveNotApplicable(context.Context) {
	r.notApplicable++
}

func TestCodeArtifactRecordsUnsupportedPolicyRequest(t *testing.T) {
	target, err := url.Parse("https://codeartifact.example.com")
	assert.NoError(t, err)
	policy := &recordingPackagePolicy{}
	strategy := &CodeArtifact{
		target:        target,
		prefix:        "/codeartifact.example.com",
		packagePolicy: policy,
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"/codeartifact.example.com/maven/repository/example.jar",
		nil,
	)

	assert.True(t, strategy.allowPackage(httptest.NewRecorder(), request))
	assert.Equal(t, 1, policy.notApplicable)
	assert.Equal(t, []string(nil), policy.purls)
}

func TestCodeArtifactEnforcesPackagePolicyBeforeOriginAuthentication(t *testing.T) {
	tests := []struct {
		name       string
		decision   packagepolicy.Decision
		err        error
		statusCode int
		policy     string
	}{
		{
			name:       "denied package",
			decision:   packagepolicy.Decision{Verdict: packagepolicy.VerdictDeny, Reasons: []string{"malware"}},
			statusCode: http.StatusForbidden,
			policy:     "deny",
		},
		{
			name:       "pending package",
			decision:   packagepolicy.Decision{Verdict: packagepolicy.VerdictPending, Reasons: []string{"pendingScan"}},
			statusCode: http.StatusServiceUnavailable,
			policy:     "pending",
		},
		{
			name:       "policy unavailable",
			err:        errors.New("Socket API unavailable"),
			statusCode: http.StatusServiceUnavailable,
			policy:     "unavailable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			var originRequests atomic.Int32
			mux, originServer, tokenServer, strategy, ctx := newTestCachingCodeArtifact(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				originRequests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			strategy.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			policy := &recordingPackagePolicy{decision: test.decision, err: test.err}
			strategy.packagePolicy = policy

			w := httptest.NewRecorder()
			path := "/npm/repository/chromatitle-js/-/chromatitle-js-1.0.0.tgz"
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, path), nil).WithContext(ctx))

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.policy, w.Header().Get("X-Cachew-Package-Policy"))
			assert.Equal(t, []string{"pkg:npm/chromatitle-js@1.0.0"}, policy.purls)
			assert.Equal(t, 0, tokenServer.requestCount())
			assert.Equal(t, int32(0), originRequests.Load())
			if test.err != nil {
				assert.Contains(t, logs.String(), test.err.Error())
			}
		})
	}
}

func TestCodeArtifactCachedPackageBypassesPackagePolicy(t *testing.T) {
	var originRequests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originRequests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, _, strategy, ctx := newTestCachingCodeArtifact(t, origin)
	policy := &recordingPackagePolicy{decision: packagepolicy.Decision{Verdict: packagepolicy.VerdictAllow}}
	strategy.packagePolicy = policy
	path := codeArtifactPath(originServer, "/npm/repository/lodash/-/lodash-4.17.21.tgz")

	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, testCodeArtifactBody, w.Body.String())
	}

	assert.Equal(t, []string{"pkg:npm/lodash@4.17.21"}, policy.purls)
	assert.Equal(t, int32(1), originRequests.Load())
}

func TestCodeArtifactSanitizesOriginTransportErrors(t *testing.T) {
	target, err := url.Parse("https://codeartifact.example.com")
	assert.NoError(t, err)
	strategy := &CodeArtifact{
		target: target,
		prefix: "/codeartifact.example.com",
		client: &http.Client{Transport: codeArtifactRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "credential=must-not-be-logged", r.URL.RawQuery)
			return nil, errors.Errorf("transport failed for %s", r.URL)
		})},
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"/codeartifact.example.com/maven/repository/package?credential=must-not-be-logged",
		nil,
	)

	_, err = strategy.do(request, "token")
	assert.EqualError(t, err, "request CodeArtifact origin")
}

func TestCodeArtifactBoundsOriginHeaderWait(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseOrigin := make(chan struct{})
	defer close(releaseOrigin)
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(requestStarted)
		<-releaseOrigin
	}))
	t.Cleanup(origin.Close)

	config := testCodeArtifactConfig(origin.URL)
	config.OriginHeaderTimeout = 25 * time.Millisecond
	mux := http.NewServeMux()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	strategy, err := newCodeArtifact(ctx, config, mux, nil, cache.NoOpCache(), true)
	assert.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/maven/repository/package"), nil)
	result := make(chan error, 1)
	go func() {
		_, requestErr := strategy.do(request, "token")
		result <- requestErr
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("origin request did not start")
	}
	select {
	case requestErr := <-result:
		assert.EqualError(t, requestErr, "request CodeArtifact origin")
	case <-time.After(time.Second):
		t.Fatal("origin header wait exceeded its deadline")
	}
}

func TestCodeArtifactBoundsOriginBodyReadIdle(t *testing.T) {
	releaseOrigin := make(chan struct{})
	defer close(releaseOrigin)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("a"))
		flusher, ok := w.(http.Flusher)
		assert.True(t, ok)
		flusher.Flush()
		<-releaseOrigin
	}))
	t.Cleanup(origin.Close)

	config := testCodeArtifactConfig(origin.URL)
	config.OriginReadIdleTimeout = 25 * time.Millisecond
	mux := http.NewServeMux()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	strategy, err := newCodeArtifact(ctx, config, mux, nil, cache.NoOpCache(), true)
	assert.NoError(t, err)
	recorded := &recordingCodeArtifactMetrics{}
	strategy.metric = recorded
	request := httptest.NewRequest(http.MethodGet, codeArtifactPath(origin, "/maven/repository/package"), nil)
	response, err := strategy.do(request, "token")
	assert.NoError(t, err)

	first := make([]byte, 1)
	n, err := response.Body.Read(first)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, "a", string(first))
	readResult := make(chan error, 1)
	go func() {
		_, readErr := response.Body.Read(make([]byte, 1))
		readResult <- readErr
	}()
	select {
	case readErr := <-readResult:
		assert.True(t, errors.Is(readErr, errCodeArtifactOriginReadIdleTimeout))
	case <-time.After(time.Second):
		t.Fatal("origin body read exceeded its idle deadline")
	}
	_ = response.Body.Close()
	assert.Equal(t, []recordedCodeArtifactOrigin{{status: "read_idle_timeout", format: "maven", size: 1}}, recorded.origin)
}

func TestCodeArtifactOriginReadIdleIgnoresConsumerPause(t *testing.T) {
	originCtx, cancel := context.WithCancelCause(t.Context())
	body := newCodeArtifactOriginBody(
		originCtx,
		io.NopCloser(strings.NewReader("ab")),
		cancel,
		25*time.Millisecond,
	)
	defer func() { assert.NoError(t, body.Close()) }()

	buffer := make([]byte, 1)
	n, err := body.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	time.Sleep(50 * time.Millisecond)
	n, err = body.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, "b", string(buffer))
}

func TestCodeArtifactOriginReadIdleResetsOnProgress(t *testing.T) {
	originCtx, cancel := context.WithCancelCause(t.Context())
	reader, writer := io.Pipe()
	body := newCodeArtifactOriginBody(originCtx, reader, cancel, 200*time.Millisecond)
	defer func() { assert.NoError(t, body.Close()) }()

	go func() {
		for _, value := range []byte("abcd") {
			time.Sleep(75 * time.Millisecond)
			_, _ = writer.Write([]byte{value})
		}
		_ = writer.Close()
	}()
	payload, err := io.ReadAll(body)
	assert.NoError(t, err)
	assert.Equal(t, "abcd", string(payload))
}

func TestCodeArtifactParentCancellationIsNotOriginReadTimeout(t *testing.T) {
	parentCtx, cancelParent := context.WithCancel(t.Context())
	originCtx, cancelOrigin := context.WithCancelCause(parentCtx)
	reader, writer := io.Pipe()
	go func() {
		<-originCtx.Done()
		_ = writer.CloseWithError(originCtx.Err())
	}()
	recorded := &recordingCodeArtifactMetrics{}
	body := &observedCodeArtifactBody{
		ReadCloser: newCodeArtifactOriginBody(originCtx, reader, cancelOrigin, time.Second),
		ctx:        parentCtx,
		metric:     recorded,
		status:     http.StatusOK,
		format:     "maven",
		started:    time.Now(),
	}
	readResult := make(chan error, 1)
	go func() {
		_, err := body.Read(make([]byte, 1))
		readResult <- err
	}()

	cancelParent()
	err := <-readResult
	assert.True(t, errors.Is(err, context.Canceled))
	assert.False(t, errors.Is(err, errCodeArtifactOriginReadIdleTimeout))
	assert.NoError(t, body.Close())
	assert.Equal(t, []recordedCodeArtifactOrigin{{status: "200", format: "maven"}}, recorded.origin)
}

func TestCodeArtifactRejectsNegativeTimeouts(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*CodeArtifactConfig)
		wantError string
	}{
		{
			name:      "origin header",
			configure: func(config *CodeArtifactConfig) { config.OriginHeaderTimeout = -time.Second },
			wantError: "codeartifact: origin-header-timeout must not be negative",
		},
		{
			name:      "origin read idle",
			configure: func(config *CodeArtifactConfig) { config.OriginReadIdleTimeout = -time.Second },
			wantError: "codeartifact: origin-read-idle-timeout must not be negative",
		},
		{
			name:      "credential",
			configure: func(config *CodeArtifactConfig) { config.CredentialTimeout = -time.Second },
			wantError: "codeartifact: credential-timeout must not be negative",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testCodeArtifactConfig("https://codeartifact.example.com")
			test.configure(&config)
			_, _, err := validateCodeArtifactConfig(config, false)
			assert.EqualError(t, err, test.wantError)
		})
	}
}

func TestCodeArtifactCachesOriginDeclaredImmutableResponses(t *testing.T) {
	paths := []string{
		"/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar",
		"/maven/repository/com/perplexity/tool/maven-metadata.xml",
		"/future-format/repository/opaque/download",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var requests atomic.Int32
			origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
				w.Header().Set("ETag", testCodeArtifactETag)
				_, _ = w.Write([]byte(testCodeArtifactBody))
			})
			mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
			requestURL := codeArtifactPath(originServer, path)

			for range 2 {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx))
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, testCodeArtifactBody, w.Body.String())
				assert.Equal(t, testCodeArtifactETag, w.Header().Get("ETag"))
			}

			assert.Equal(t, int32(1), requests.Load(), "the second request should hit Cachew")
			assert.Equal(t, 1, tokenServer.requestCount(), "a cache hit should not request origin authorization")
		})
	}
}

func TestCodeArtifactPreservesValidatorsAcrossCacheHits(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("ETag", testCodeArtifactETag)
		w.Header().Set("Last-Modified", testCodeArtifactModified)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	prime := httptest.NewRecorder()
	mux.ServeHTTP(prime, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
	assert.Equal(t, http.StatusOK, prime.Code)
	assert.Equal(t, testCodeArtifactETag, prime.Header().Get("ETag"))
	assert.Equal(t, testCodeArtifactModified, prime.Header().Get("Last-Modified"))

	tests := []struct {
		name       string
		headers    http.Header
		statusCode int
		body       string
	}{
		{name: "matching If-None-Match", headers: http.Header{"If-None-Match": {testCodeArtifactETag}}, statusCode: http.StatusNotModified},
		{name: "weak If-None-Match", headers: http.Header{"If-None-Match": {`W/"asset-v1"`}}, statusCode: http.StatusNotModified},
		{name: "matching If-Match", headers: http.Header{"If-Match": {testCodeArtifactETag}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "matching If-Match list", headers: http.Header{"If-Match": {`"asset-v0", "asset-v1"`}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "failed If-Match", headers: http.Header{"If-Match": {`"asset-v0"`}}, statusCode: http.StatusPreconditionFailed},
		{name: "weak If-Match fails", headers: http.Header{"If-Match": {`W/"asset-v1"`}}, statusCode: http.StatusPreconditionFailed},
		{name: "not modified since", headers: http.Header{"If-Modified-Since": {testCodeArtifactModified}}, statusCode: http.StatusNotModified},
		{name: "modified since", headers: http.Header{"If-Modified-Since": {testCodeArtifactBeforeModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "failed unmodified since", headers: http.Header{"If-Unmodified-Since": {testCodeArtifactBeforeModified}}, statusCode: http.StatusPreconditionFailed},
		{name: "unmodified since", headers: http.Header{"If-Unmodified-Since": {testCodeArtifactModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "If-Unmodified-Since precedence", headers: http.Header{"If-Unmodified-Since": {testCodeArtifactBeforeModified}, "If-None-Match": {testCodeArtifactETag}}, statusCode: http.StatusPreconditionFailed},
		{name: "If-None-Match precedence", headers: http.Header{"If-None-Match": {`"asset-v0"`}, "If-Modified-Since": {testCodeArtifactModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "If-Match precedence", headers: http.Header{"If-Match": {testCodeArtifactETag}, "If-Unmodified-Since": {testCodeArtifactBeforeModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "invalid date ignored", headers: http.Header{"If-Modified-Since": {"not-a-date"}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
			req.Header = test.headers
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.body, w.Body.String())
			if test.statusCode != http.StatusPreconditionFailed {
				assert.Equal(t, testCodeArtifactETag, w.Header().Get("ETag"))
				assert.Equal(t, testCodeArtifactModified, w.Header().Get("Last-Modified"))
			}
		})
	}

	assert.Equal(t, int32(1), requests.Load(), "validator requests should use the cached representation")
	assert.Equal(t, 1, tokenServer.requestCount(), "validator cache hits should not request origin authorization")
}

func TestCodeArtifactCachesImmutableResponsesWithMalformedETags(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("ETag", testCodeArtifactMalformedETag)
		w.Header().Set("Last-Modified", testCodeArtifactModified)
		w.Header().Set("Vary", "Accept")
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/pypi/repository/simple/pip/0.2.1/pip-0.2.1.tar.gz")

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
		req.Header.Set("Accept", "application/octet-stream")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, testCodeArtifactBody, w.Body.String())
		assert.Equal(t, "", w.Header().Get("ETag"))
		assert.Equal(t, testCodeArtifactModified, w.Header().Get("Last-Modified"))
	}

	assert.Equal(t, int32(1), requests.Load(), "the malformed optional ETag must not prevent caching")
	assert.Equal(t, 1, tokenServer.requestCount(), "a cache hit should not request origin authorization")
}

func TestCodeArtifactDoesNotCacheUnsupportedOriginETags(t *testing.T) {
	const weakETag = `W/"asset-v1"`
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("ETag", weakETag)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, weakETag, w.Header().Get("ETag"))
		assert.Equal(t, testCodeArtifactBody, w.Body.String())
	}

	assert.Equal(t, int32(2), requests.Load(), "an origin validator Cachew cannot preserve must bypass cache")
}

func TestCodeArtifactRequiresImmutableOriginPolicy(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", testCodeArtifactETag)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/npm/repository/package/-/package-1.2.3.tgz")

	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, testCodeArtifactBody, w.Body.String())
	}

	assert.Equal(t, int32(2), requests.Load(), "Cachew must honor the origin's mutable cache policy")
}

func TestCodeArtifactCachesAcceptVariantsSeparately(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		w.Header().Set("Vary", "Accept")
		_, _ = io.WriteString(w, r.Header.Get("Accept"))
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/future-format/repository/opaque/download")

	for range 2 {
		for _, accept := range []string{"application/json", "application/octet-stream"} {
			req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
			req.Header.Set("Accept", accept)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, accept, w.Body.String())
		}
	}

	assert.Equal(t, int32(2), requests.Load(), "each representation should populate once")
}

func TestCodeArtifactRejectsUnsafeSharedCachePolicies(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		vary         string
		setCookie    string
	}{
		{name: "missing public", cacheControl: "max-age=3600, immutable"},
		{name: "missing freshness", cacheControl: "public, immutable"},
		{name: "zero freshness", cacheControl: "public, max-age=0, immutable"},
		{name: "no store", cacheControl: "public, max-age=3600, immutable, no-store"},
		{name: "no cache", cacheControl: "public, max-age=3600, immutable, no-cache"},
		{name: "private", cacheControl: "public, max-age=3600, immutable, private"},
		{name: "vary wildcard", cacheControl: testCodeArtifactCacheControl, vary: "*"},
		{name: "unsupported vary", cacheControl: testCodeArtifactCacheControl, vary: "User-Agent"},
		{name: "sets cookie", cacheControl: testCodeArtifactCacheControl, setCookie: "session=secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := http.Header{
				"Cache-Control": {test.cacheControl},
				"Vary":          {test.vary},
				"Set-Cookie":    {test.setCookie},
			}
			_, _, _, cacheable := codeArtifactCacheEntry(headers, time.Now())
			assert.False(t, cacheable)
		})
	}
}

func TestCodeArtifactUsesRemainingSharedFreshness(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	headers := http.Header{
		"Cache-Control": {"public, max-age=3600, s-maxage=600, immutable"},
		"Age":           {"120"},
	}
	_, ttl, _, cacheable := codeArtifactCacheEntry(headers, now)

	assert.True(t, cacheable)
	assert.Equal(t, 8*time.Minute, ttl)
}

func TestCodeArtifactAdvancesAgeOnCacheHits(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	headers := http.Header{
		"Cache-Control":     {"public, max-age=3600, s-maxage=600, immutable"},
		cache.ExpirationKey: {now.Add(8 * time.Minute).Format(time.RFC3339Nano)},
	}

	originHeaders := codeArtifactOriginHeaders(headers, now)

	assert.Equal(t, "120", originHeaders.Get("Age"))
	assert.Equal(t, "", originHeaders.Get(cache.ExpirationKey))
}

func TestCodeArtifactDoesNotExposeGeneratedValidators(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		_, _ = w.Write([]byte(testCodeArtifactBody))
	})
	mux, originServer, tokenServer, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	tests := []struct {
		name       string
		headers    http.Header
		statusCode int
		body       string
	}{
		{name: "cold response", statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "warm response", statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "date condition ignored", headers: http.Header{"If-Modified-Since": {testCodeArtifactFutureModified}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
		{name: "wildcard If-None-Match", headers: http.Header{"If-None-Match": {"*"}}, statusCode: http.StatusNotModified},
		{name: "wildcard If-Match", headers: http.Header{"If-Match": {"*"}}, statusCode: http.StatusOK, body: testCodeArtifactBody},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
			req.Header = test.headers
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			assert.Equal(t, test.statusCode, w.Code)
			assert.Equal(t, test.body, w.Body.String())
			assert.Equal(t, "", w.Header().Get("ETag"))
			assert.Equal(t, "", w.Header().Get("Last-Modified"))
			assert.Equal(t, "", w.Header().Get(codeArtifactOriginValidatorsHeader))
		})
	}

	assert.Equal(t, int32(1), requests.Load(), "cache metadata must not leak as origin validators")
	assert.Equal(t, 1, tokenServer.requestCount())
}

func TestCodeArtifactDoesNotCacheRangesOrUnsuccessfulResponses(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		if r.URL.Query().Has("missing") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Range") != "" {
			w.Header().Set("Content-Range", "bytes 0-3/7")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte("part"))
			return
		}
		_, _ = w.Write([]byte("complete"))
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx)
		req.Header.Set("Range", "bytes=0-3")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusPartialContent, w.Code)
		assert.Equal(t, "part", w.Body.String())
	}
	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL+"?missing", nil).WithContext(ctx))
		assert.Equal(t, http.StatusNotFound, w.Code)
	}
	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "complete", w.Body.String())
	}

	assert.Equal(t, int32(5), requests.Load(), "only the final full response should populate cache")
}

func TestCodeArtifactDoesNotCacheIncompleteResponses(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		hijacker, ok := w.(http.Hijacker)
		assert.True(t, ok)
		conn, output, err := hijacker.Hijack()
		assert.NoError(t, err)
		defer conn.Close()
		_, _ = output.WriteString("HTTP/1.1 200 OK\r\nCache-Control: public, max-age=3600, immutable\r\nContent-Length: 20\r\n\r\nshort")
		assert.NoError(t, output.Flush())
	})
	mux, originServer, _, _, ctx := newTestCachingCodeArtifact(t, origin)
	assetURL := codeArtifactPath(originServer, "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar")

	for range 2 {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, assetURL, nil).WithContext(ctx))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "short", w.Body.String())
	}

	assert.Equal(t, int32(2), requests.Load(), "an interrupted body must abort the cache entry")
}

type recordingCodeArtifactMetrics struct {
	requests []codeArtifactCacheMode
	cache    []recordedCodeArtifactCacheEvent
	auth     []codeArtifactAuthEvent
	origin   []recordedCodeArtifactOrigin
	redirect []codeArtifactRedirectEvent
}

type recordedCodeArtifactCacheEvent struct {
	event codeArtifactCacheEvent
	tier  codeArtifactCacheTier
}

type recordedCodeArtifactOrigin struct {
	status string
	format string
	size   int64
}

func (m *recordingCodeArtifactMetrics) recordRequest(_ context.Context, mode codeArtifactCacheMode) {
	m.requests = append(m.requests, mode)
}

func (m *recordingCodeArtifactMetrics) recordCache(
	_ context.Context,
	event codeArtifactCacheEvent,
	tier codeArtifactCacheTier,
) {
	m.cache = append(m.cache, recordedCodeArtifactCacheEvent{event: event, tier: tier})
}

func (m *recordingCodeArtifactMetrics) recordAuth(_ context.Context, event codeArtifactAuthEvent) {
	m.auth = append(m.auth, event)
}

func (m *recordingCodeArtifactMetrics) recordOrigin(_ context.Context, observation codeArtifactOriginObservation) {
	m.origin = append(m.origin, recordedCodeArtifactOrigin{
		status: observation.status,
		format: observation.format,
		size:   observation.size,
	})
}

func (m *recordingCodeArtifactMetrics) recordRedirect(_ context.Context, event codeArtifactRedirectEvent) {
	m.redirect = append(m.redirect, event)
}

func TestCodeArtifactMetricsExposeOnlyBoundedDecisions(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/immutable-payload") {
			w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		}
		_, _ = w.Write([]byte("payload"))
	})
	mux, originServer, _, strategy, ctx := newTestCachingCodeArtifact(t, origin)
	recorded := &recordingCodeArtifactMetrics{}
	strategy.metric = recorded
	immutable := codeArtifactPath(originServer, "/future-format/repository/opaque/immutable-payload")
	mutable := codeArtifactPath(originServer, "/pypi/repository/simple/private-package/")

	for _, requestURL := range []string{immutable, immutable, mutable} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx))
	}

	assert.Equal(t, []codeArtifactCacheMode{
		codeArtifactCacheLookup,
		codeArtifactCacheLookup,
		codeArtifactCacheLookup,
	}, recorded.requests)
	assert.Equal(t, []recordedCodeArtifactCacheEvent{
		{event: codeArtifactCacheMiss, tier: codeArtifactCacheTierNone},
		{event: codeArtifactCacheStored, tier: codeArtifactCacheTierAll},
		{event: codeArtifactCacheHit, tier: "memory"},
		{event: codeArtifactCacheMiss, tier: codeArtifactCacheTierNone},
		{event: codeArtifactCacheNotCacheable, tier: codeArtifactCacheTierNone},
	}, recorded.cache)
	assert.Equal(t, []codeArtifactAuthEvent{codeArtifactAuthRefresh, codeArtifactAuthReuse}, recorded.auth)
	assert.Equal(t, []recordedCodeArtifactOrigin{
		{status: "200", format: "other", size: 7},
		{status: "200", format: "pypi", size: 7},
	}, recorded.origin)
	assert.Equal(t, []codeArtifactRedirectEvent(nil), recorded.redirect)
}

type countingCache struct {
	cache.Cache
	opens   atomic.Int32
	creates atomic.Int32
}

type synchronizedOpenCache struct {
	cache.Cache
	waitFor int32
	opens   atomic.Int32
	ready   chan struct{}
}

func (c *synchronizedOpenCache) Namespace(cache.Namespace) cache.Cache {
	return c
}

func (c *synchronizedOpenCache) Open(
	ctx context.Context,
	key cache.Key,
	opts ...cache.Option,
) (io.ReadCloser, http.Header, error) {
	opened := c.opens.Add(1)
	if opened <= c.waitFor {
		if opened == c.waitFor {
			close(c.ready)
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-c.ready:
		}
	}
	return c.Cache.Open(ctx, key, opts...)
}

func (c *countingCache) Namespace(cache.Namespace) cache.Cache {
	return c
}

func (c *countingCache) Open(ctx context.Context, key cache.Key, opts ...cache.Option) (io.ReadCloser, http.Header, error) {
	c.opens.Add(1)
	return c.Cache.Open(ctx, key, opts...)
}

func (c *countingCache) Create(ctx context.Context, key cache.Key, headers http.Header, ttl time.Duration, opts ...cache.Option) (cache.Writer, error) {
	c.creates.Add(1)
	return c.Cache.Create(ctx, key, headers, ttl, opts...)
}

func TestCodeArtifactCoalescesConcurrentImmutableCacheFills(t *testing.T) {
	const callers = 8
	var originRequests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originRequests.Add(1)
		w.Header().Set("Cache-Control", testCodeArtifactCacheControl)
		_, _ = io.WriteString(w, testCodeArtifactBody)
	})
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	barrier := &synchronizedOpenCache{Cache: memory, waitFor: callers, ready: make(chan struct{})}
	mux := http.NewServeMux()
	_, err = newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), barrier, true)
	assert.NoError(t, err)
	requestURL := codeArtifactPath(originServer, "/future-format/repository/opaque/download")

	start := make(chan struct{})
	responses := make(chan string, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx))
			assert.Equal(t, http.StatusOK, w.Code)
			responses <- w.Body.String()
		}()
	}
	close(start)
	wg.Wait()
	close(responses)

	for body := range responses {
		assert.Equal(t, testCodeArtifactBody, body)
	}
	assert.Equal(t, int32(1), originRequests.Load())
	assert.Equal(t, 1, tokenServer.requestCount())
}

func TestCodeArtifactMutableAndUnknownPathsAreNotStored(t *testing.T) {
	tests := []struct {
		path       string
		wantLookup bool
	}{
		{path: "/maven/repository/com/perplexity/tool/maven-metadata.xml", wantLookup: true},
		{path: "/maven/repository/com/perplexity/tool/1.2.3/tool-1.2.3.jar?download=1", wantLookup: false},
		{path: "/future-format/repository/opaque/download", wantLookup: true},
	}
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("current"))
	})
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	tracked := &countingCache{Cache: cache.NoOpCache()}
	mux := http.NewServeMux()
	_, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), tracked, true)
	assert.NoError(t, err)

	var wantOpens int32
	for _, test := range tests {
		if test.wantLookup {
			wantOpens += 2
		}
		for range 2 {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, test.path), nil).WithContext(ctx))
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "current", w.Body.String())
		}
	}

	assert.Equal(t, int32(2*len(tests)), requests.Load())
	assert.Equal(t, wantOpens, tracked.opens.Load(), "only lookup requests should check the cache")
	assert.Equal(t, int32(0), tracked.creates.Load(), "responses without origin immutability must not be stored")
}

func TestCodeArtifactPassesThroughReadSemantics(t *testing.T) {
	type observedRequest struct {
		method         string
		escapedPath    string
		rawQuery       string
		authorization  string
		cookie         string
		packageAuth    string
		rangeHeader    string
		ifNoneMatch    string
		removedHeader  string
		acceptEncoding string
	}
	var mu sync.Mutex
	var observed []observedRequest
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observed = append(observed, observedRequest{
			method:         r.Method,
			escapedPath:    r.URL.EscapedPath(),
			rawQuery:       r.URL.RawQuery,
			authorization:  r.Header.Get("Authorization"),
			cookie:         r.Header.Get("Cookie"),
			packageAuth:    r.Header.Get("X-Package-Authorization"),
			rangeHeader:    r.Header.Get("Range"),
			ifNoneMatch:    r.Header.Get("If-None-Match"),
			removedHeader:  r.Header.Get("X-Remove"),
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		})
		mu.Unlock()

		w.Header().Set("ETag", `"asset-v1"`)
		w.Header().Set("Content-Range", "bytes 0-6/12")
		w.Header().Set("Connection", "X-Origin-Hop")
		w.Header().Set("X-Origin-Hop", "remove-me")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("payload"))
	})

	expiresAt := time.Now().Add(time.Hour)
	mux, originServer, tokenServer, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "service-token", expiresAt: expiresAt})
	requestURL := codeArtifactPath(originServer, "/maven/repository/pkg%2Fname/file.whl?version=1&download=true")

	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, requestURL, nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer client-token")
		req.Header.Set("Cookie", "session=client-secret")
		req.Header.Set("X-Package-Authorization", "client-package-token")
		req.Header.Set("Range", "bytes=0-6")
		req.Header.Set("If-None-Match", `"asset-v0"`)
		req.Header.Set("Connection", "X-Remove")
		req.Header.Set("X-Remove", "remove-me")
		if i == 0 {
			req.Header.Set("Accept-Encoding", "gzip")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusPartialContent, w.Code)
		assert.Equal(t, "payload", w.Body.String())
		assert.Equal(t, `"asset-v1"`, w.Header().Get("ETag"))
		assert.Equal(t, "bytes 0-6/12", w.Header().Get("Content-Range"))
		assert.Equal(t, "", w.Header().Get("X-Origin-Hop"))
	}

	mu.Lock()
	requests := append([]observedRequest(nil), observed...)
	mu.Unlock()
	assert.Equal(t, 2, len(requests), "pass-through responses must not be cached")
	assert.Equal(t, http.MethodGet, requests[0].method)
	assert.Equal(t, "/maven/repository/pkg%2Fname/file.whl", requests[0].escapedPath)
	assert.Equal(t, "version=1&download=true", requests[0].rawQuery)
	password, ok := decodeBasicPassword(requests[0].authorization)
	assert.True(t, ok)
	assert.Equal(t, "service-token", password)
	assert.Equal(t, "", requests[0].cookie)
	assert.Equal(t, "", requests[0].packageAuth)
	assert.Equal(t, "bytes=0-6", requests[0].rangeHeader)
	assert.Equal(t, `"asset-v0"`, requests[0].ifNoneMatch)
	assert.Equal(t, "", requests[0].removedHeader)
	assert.Equal(t, "gzip", requests[0].acceptEncoding)
	assert.Equal(t, "", requests[1].acceptEncoding)
	assert.Equal(t, 1, tokenServer.requestCount(), "a valid token should be reused")
	assert.Equal(t, http.MethodPost, tokenServer.method)
	assert.Equal(t, "/v1/authorization-token", tokenServer.path)
	assert.Equal(t, testCodeArtifactDomain, tokenServer.query.Get("domain"))
	assert.Equal(t, testCodeArtifactDomainOwner, tokenServer.query.Get("domain-owner"))
}

func TestCodeArtifactUsesCargoTokenAuthorization(t *testing.T) {
	const serviceToken = "cargo-service-token"
	var authorization string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("crate"))
	})
	mux, originServer, _, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: serviceToken, expiresAt: time.Now().Add(time.Hour)},
	)
	req := httptest.NewRequest(
		http.MethodGet,
		codeArtifactPath(originServer, "/cargo/repository/crates/package/1.2.3"),
		nil,
	).WithContext(ctx)
	req.Header.Set("Authorization", "client-token")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "crate", w.Body.String())
	assert.Equal(t, serviceToken, authorization)
}

func TestCodeArtifactRewritesMetadataHEADWithoutBody(t *testing.T) {
	var method string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "123")
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("must not reach client"))
	})
	mux, originServer, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})

	req := httptest.NewRequest(http.MethodHead, codeArtifactPath(originServer, "/npm/repository/package"), nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, http.MethodHead, method)
	assert.Equal(t, "", w.Body.String())
	assert.Equal(t, "", w.Header().Get("Content-Length"))
	assert.Equal(t, "", w.Header().Get("Last-Modified"))
}

func TestCodeArtifactRefreshesRejectedTokenOnce(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		password, _ := decodeBasicPassword(r.Header.Get("Authorization"))
		if password == "stale-token" {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "fresh-token", password)
		_, _ = w.Write([]byte("ok"))
	})
	now := time.Now()
	mux, originServer, tokenServer, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: "stale-token", expiresAt: now.Add(time.Hour)},
		tokenResponse{token: "fresh-token", expiresAt: now.Add(2 * time.Hour)},
	)

	req := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/pypi/repository/simple/pkg/"), nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
	assert.Equal(t, int32(2), requests.Load())
	assert.Equal(t, 2, tokenServer.requestCount())
}

func TestCodeArtifactReturnsSecondAuthorizationFailure(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "denied", http.StatusForbidden)
	})
	now := time.Now()
	mux, originServer, tokenServer, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: "token-1", expiresAt: now.Add(time.Hour)},
		tokenResponse{token: "token-2", expiresAt: now.Add(2 * time.Hour)},
	)

	req := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/generic/repository/file"), nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "denied\n", w.Body.String())
	assert.Equal(t, "30", w.Header().Get("Retry-After"))
	assert.Equal(t, int32(2), requests.Load(), "authorization failure must have only one retry")
	assert.Equal(t, 2, tokenServer.requestCount())
}

func TestCodeArtifactTokenRefreshesCoalesce(t *testing.T) {
	now := time.Now()
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "token-1", expiresAt: now.Add(time.Hour)},
		tokenResponse{token: "token-1", expiresAt: now.Add(2 * time.Hour)},
	)
	manager := tokenServer.tokenManager(func() time.Time { return now })

	const callers = 16
	start := make(chan struct{})
	tokens := make(chan string, callers)
	errorsCh := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			token, err := manager.Token(t.Context(), 0)
			tokens <- token.value
			errorsCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(tokens)
	close(errorsCh)

	for err := range errorsCh {
		assert.NoError(t, err)
	}
	for token := range tokens {
		assert.Equal(t, "token-1", token)
	}
	assert.Equal(t, 1, tokenServer.requestCount())

	start = make(chan struct{})
	tokens = make(chan string, callers)
	errorsCh = make(chan error, callers)
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			token, err := manager.Token(t.Context(), 1)
			tokens <- token.value
			errorsCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(tokens)
	close(errorsCh)

	for err := range errorsCh {
		assert.NoError(t, err)
	}
	for token := range tokens {
		assert.Equal(t, "token-1", token)
	}
	assert.Equal(t, 2, tokenServer.requestCount(), "forced refreshes should coalesce")
}

func TestCodeArtifactTokenRefreshHasDeadline(t *testing.T) {
	client := codeArtifactAuthorizationClientFunc(func(
		ctx context.Context,
		_ *awscodeartifact.GetAuthorizationTokenInput,
		_ ...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	config := testCodeArtifactConfig("https://codeartifact.example.com")
	config.CredentialTimeout = 25 * time.Millisecond
	manager := newCodeArtifactTokenManagerWithClient(config, client, time.Now)
	result := make(chan error, 1)
	go func() {
		_, err := manager.Token(t.Context(), 0)
		result <- err
	}()

	select {
	case err := <-result:
		assert.True(t, errors.Is(err, context.DeadlineExceeded))
	case <-time.After(time.Second):
		t.Fatal("credential refresh exceeded its deadline")
	}
}

func TestCodeArtifactTokenWaitRespectsCallerDeadline(t *testing.T) {
	refreshStarted := make(chan struct{}, 1)
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	defer release()
	var requests atomic.Int32
	expiresAt := time.Now().Add(time.Hour)
	client := codeArtifactAuthorizationClientFunc(func(
		ctx context.Context,
		_ *awscodeartifact.GetAuthorizationTokenInput,
		_ ...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
		requests.Add(1)
		refreshStarted <- struct{}{}
		select {
		case <-releaseRefresh:
			return &awscodeartifact.GetAuthorizationTokenOutput{
				AuthorizationToken: aws.String("token"),
				Expiration:         &expiresAt,
			}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	config := testCodeArtifactConfig("https://codeartifact.example.com")
	config.CredentialTimeout = time.Second
	manager := newCodeArtifactTokenManagerWithClient(config, client, time.Now)
	firstResult := make(chan error, 1)
	go func() {
		_, err := manager.Token(t.Context(), 0)
		firstResult <- err
	}()

	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("credential refresh did not start")
	}
	waitCtx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, err := manager.Token(waitCtx, 0)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	release()
	assert.NoError(t, <-firstResult)
	assert.Equal(t, int32(1), requests.Load())
}

func TestCodeArtifactTokenReuseContinuesDuringForcedRefresh(t *testing.T) {
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	defer release()
	var requests atomic.Int32
	expiresAt := time.Now().Add(time.Hour)
	client := codeArtifactAuthorizationClientFunc(func(
		ctx context.Context,
		_ *awscodeartifact.GetAuthorizationTokenInput,
		_ ...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
		if requests.Add(1) == 2 {
			close(refreshStarted)
			select {
			case <-releaseRefresh:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &awscodeartifact.GetAuthorizationTokenOutput{
			AuthorizationToken: aws.String(fmt.Sprintf("token-%d", requests.Load())),
			Expiration:         &expiresAt,
		}, nil
	})
	config := testCodeArtifactConfig("https://codeartifact.example.com")
	config.CredentialTimeout = time.Second
	manager := newCodeArtifactTokenManagerWithClient(config, client, time.Now)
	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	forcedResult := make(chan codeArtifactToken, 1)
	forcedError := make(chan error, 1)
	go func() {
		token, refreshErr := manager.Token(t.Context(), first.generation)
		forcedResult <- token
		forcedError <- refreshErr
	}()

	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("forced credential refresh did not start")
	}
	reused, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	assert.Equal(t, first.value, reused.value)
	assert.Equal(t, codeArtifactAuthReuse, reused.event)
	release()
	assert.NoError(t, <-forcedError)
	refreshed := <-forcedResult
	assert.Equal(t, "token-2", refreshed.value)
	assert.Equal(t, int32(2), requests.Load())
}

func TestCodeArtifactTokenReuseContinuesDuringProactiveRefresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	currentTime := now
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRefresh) }) }
	defer release()
	var requests atomic.Int32
	client := codeArtifactAuthorizationClientFunc(func(
		ctx context.Context,
		_ *awscodeartifact.GetAuthorizationTokenInput,
		_ ...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
		request := requests.Add(1)
		expiresAt := now.Add(12 * time.Hour)
		if request == 2 {
			close(refreshStarted)
			select {
			case <-releaseRefresh:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			expiresAt = now.Add(23 * time.Hour)
		}
		return &awscodeartifact.GetAuthorizationTokenOutput{
			AuthorizationToken: aws.String(fmt.Sprintf("token-%d", request)),
			Expiration:         &expiresAt,
		}, nil
	})
	config := testCodeArtifactConfig("https://codeartifact.example.com")
	config.CredentialTimeout = time.Second
	manager := newCodeArtifactTokenManagerWithClient(config, client, func() time.Time { return currentTime })
	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	currentTime = now.Add(11 * time.Hour)

	refreshResult := make(chan codeArtifactToken, 1)
	refreshError := make(chan error, 1)
	go func() {
		token, refreshErr := manager.Token(t.Context(), 0)
		refreshResult <- token
		refreshError <- refreshErr
	}()
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("proactive credential refresh did not start")
	}

	reuseCtx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	reused, err := manager.Token(reuseCtx, 0)
	assert.NoError(t, err)
	assert.Equal(t, first.value, reused.value)
	assert.Equal(t, codeArtifactAuthReuse, reused.event)
	release()
	assert.NoError(t, <-refreshError)
	refreshed := <-refreshResult
	assert.Equal(t, "token-2", refreshed.value)
	assert.Equal(t, codeArtifactAuthRefresh, refreshed.event)
	assert.Equal(t, int32(2), requests.Load())
}

func TestCodeArtifactProactiveRefreshOutlivesCallerCancellation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	currentTime := now
	refreshStarted := make(chan struct{})
	callerCanceled := make(chan struct{})
	var requests atomic.Int32
	client := codeArtifactAuthorizationClientFunc(func(
		ctx context.Context,
		_ *awscodeartifact.GetAuthorizationTokenInput,
		_ ...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
		request := requests.Add(1)
		expiresAt := now.Add(12 * time.Hour)
		if request == 2 {
			close(refreshStarted)
			<-callerCanceled
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			expiresAt = now.Add(23 * time.Hour)
		}
		return &awscodeartifact.GetAuthorizationTokenOutput{
			AuthorizationToken: aws.String(fmt.Sprintf("token-%d", request)),
			Expiration:         &expiresAt,
		}, nil
	})
	manager := newCodeArtifactTokenManagerWithClient(
		testCodeArtifactConfig("https://codeartifact.example.com"),
		client,
		func() time.Time { return currentTime },
	)
	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	currentTime = now.Add(11 * time.Hour)
	requestCtx, cancelRequest := context.WithCancel(t.Context())
	result := make(chan codeArtifactToken, 1)
	resultErr := make(chan error, 1)
	go func() {
		token, refreshErr := manager.Token(requestCtx, 0)
		result <- token
		resultErr <- refreshErr
	}()
	<-refreshStarted
	cancelRequest()
	close(callerCanceled)

	assert.NoError(t, <-resultErr)
	refreshed := <-result
	assert.Equal(t, "token-2", refreshed.value)
	assert.Equal(t, codeArtifactAuthRefresh, refreshed.event)
	assert.Equal(t, first.generation+1, refreshed.generation)
	assert.True(t, manager.retryAfter.IsZero())
}

func TestCodeArtifactRefreshesBeforeExpiration(t *testing.T) {
	testCases := []struct {
		name         string
		lifetime     time.Duration
		refreshAfter time.Duration
	}{
		{name: "default lifetime", lifetime: 12 * time.Hour, refreshAfter: 11 * time.Hour},
		{name: "short lifetime", lifetime: 30 * time.Minute, refreshAfter: 15 * time.Minute},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			currentTime := now
			tokenServer := newLocalTokenServer(
				t,
				tokenResponse{token: "token-1", expiresAt: now.Add(testCase.lifetime)},
				tokenResponse{token: "token-2", expiresAt: now.Add(2 * testCase.lifetime)},
			)
			manager := tokenServer.tokenManager(func() time.Time { return currentTime })

			first, err := manager.Token(t.Context(), 0)
			assert.NoError(t, err)
			currentTime = now.Add(testCase.refreshAfter - time.Nanosecond)
			reused, err := manager.Token(t.Context(), 0)
			assert.NoError(t, err)
			assert.Equal(t, first.value, reused.value)
			assert.Equal(t, 1, tokenServer.requestCount())

			currentTime = now.Add(testCase.refreshAfter)
			refreshed, err := manager.Token(t.Context(), 0)
			assert.NoError(t, err)
			assert.Equal(t, "token-2", refreshed.value)
			assert.Equal(t, codeArtifactAuthRefresh, refreshed.event)
			assert.Equal(t, 2, tokenServer.requestCount())
		})
	}
}

func TestCodeArtifactRefreshFailureFallsBackOnlyToUnrejectedToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	currentTime := now
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "near-expiry", expiresAt: now.Add(time.Minute)},
		tokenResponse{status: http.StatusServiceUnavailable},
	)
	manager := tokenServer.tokenManager(func() time.Time { return currentTime })

	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	currentTime = now.Add(30 * time.Second)
	fallback, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	assert.Equal(t, first.value, fallback.value)
	assert.Equal(t, first.generation, fallback.generation)
	assert.Equal(t, codeArtifactAuthFailure, fallback.event)

	_, err = manager.Token(t.Context(), first.generation)
	assert.Error(t, err)
}

func TestCodeArtifactFailedProactiveRefreshesBackOff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	currentTime := now
	expiresAt := now.Add(12 * time.Hour)
	var requests atomic.Int32
	client := codeArtifactAuthorizationClientFunc(func(
		context.Context,
		*awscodeartifact.GetAuthorizationTokenInput,
		...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error) {
		if requests.Add(1) == 1 {
			return &awscodeartifact.GetAuthorizationTokenOutput{
				AuthorizationToken: aws.String("near-expiry"),
				Expiration:         &expiresAt,
			}, nil
		}
		return nil, errors.New("token service unavailable")
	})
	manager := newCodeArtifactTokenManagerWithClient(testCodeArtifactConfig("https://codeartifact.example.com"), client, func() time.Time {
		return currentTime
	})

	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	currentTime = now.Add(11 * time.Hour)

	const callers = 16
	start := make(chan struct{})
	tokens := make(chan codeArtifactToken, callers)
	errorsCh := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			token, tokenErr := manager.Token(t.Context(), 0)
			tokens <- token
			errorsCh <- tokenErr
		}()
	}
	close(start)
	wg.Wait()
	close(tokens)
	close(errorsCh)

	for tokenErr := range errorsCh {
		assert.NoError(t, tokenErr)
	}
	events := map[codeArtifactAuthEvent]int{}
	for token := range tokens {
		assert.Equal(t, first.value, token.value)
		assert.Equal(t, first.generation, token.generation)
		events[token.event]++
	}
	assert.Equal(t, 1, events[codeArtifactAuthFailure])
	assert.Equal(t, callers-1, events[codeArtifactAuthReuse])
	assert.Equal(t, int32(2), requests.Load(), "failed proactive refreshes should back off")

	currentTime = now.Add(11*time.Hour + codeArtifactTokenRefreshFailureBackoff)
	retry, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	assert.Equal(t, codeArtifactAuthFailure, retry.event)
	assert.Equal(t, int32(3), requests.Load(), "refresh should retry after the backoff")
}

func TestCodeArtifactDeniesWritesBeforeOrigin(t *testing.T) {
	var requests atomic.Int32
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux, originServer, _, ctx := newTestCodeArtifact(t, origin, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	path := codeArtifactPath(originServer, "/maven/repository/package")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, path, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, method)
	}
	assert.Equal(t, int32(0), requests.Load())
}

func TestCodeArtifactRewritesSameOriginAndFollowsCrossOriginRedirects(t *testing.T) {
	type observedDownload struct {
		authorization      string
		proxyAuthorization string
		cookie             string
		packageAuth        string
		rangeHeader        string
		ifNoneMatch        string
		acceptEncoding     string
		rawQuery           string
	}
	var downloadRequest observedDownload
	download := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloadRequest = observedDownload{
			authorization:      r.Header.Get("Authorization"),
			proxyAuthorization: r.Header.Get("Proxy-Authorization"),
			cookie:             r.Header.Get("Cookie"),
			packageAuth:        r.Header.Get("X-Package-Authorization"),
			rangeHeader:        r.Header.Get("Range"),
			ifNoneMatch:        r.Header.Get("If-None-Match"),
			acceptEncoding:     r.Header.Get("Accept-Encoding"),
			rawQuery:           r.URL.RawQuery,
		}
		_, _ = w.Write([]byte("asset"))
	}))
	t.Cleanup(download.Close)

	var originURL string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, originURL+"/maven/repository/final?download=1", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, download.URL+"/asset?X-Amz-Signature=secret", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
	originServer := httptest.NewServer(origin)
	t.Cleanup(originServer.Close)
	tokenServer := newLocalTokenServer(t, tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)})
	_, ctx := logging.Configure(context.Background(), logging.Config{Level: slog.LevelError})
	mux := http.NewServeMux()
	strategy, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), cache.NoOpCache(), true)
	assert.NoError(t, err)
	recorded := &recordingCodeArtifactMetrics{}
	strategy.metric = recorded
	strategy.client.Transport = download.Client().Transport
	originURL = originServer.URL

	same := httptest.NewRecorder()
	mux.ServeHTTP(same, httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/same"), nil).WithContext(ctx))
	assert.Equal(t, http.StatusFound, same.Code)
	assert.Equal(t, codeArtifactPath(originServer, "/maven/repository/final?download=1"), same.Header().Get("Location"))

	crossRequest := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/cross"), nil).WithContext(ctx)
	crossRequest.Header.Set("Authorization", "Bearer client-token")
	crossRequest.Header.Set("Proxy-Authorization", "Basic client-proxy-token")
	crossRequest.Header.Set("Cookie", "session=client-secret")
	crossRequest.Header.Set("X-Package-Authorization", "client-package-token")
	crossRequest.Header.Set("Range", "bytes=0-4")
	crossRequest.Header.Set("If-None-Match", `"asset-v1"`)
	crossRequest.Header.Set("Accept-Encoding", "gzip")
	cross := httptest.NewRecorder()
	mux.ServeHTTP(cross, crossRequest)
	assert.Equal(t, http.StatusOK, cross.Code)
	assert.Equal(t, "asset", cross.Body.String())
	assert.Equal(t, "", cross.Header().Get("Location"))
	assert.Equal(t, observedDownload{
		authorization:      "",
		proxyAuthorization: "",
		cookie:             "",
		packageAuth:        "",
		rangeHeader:        "bytes=0-4",
		ifNoneMatch:        `"asset-v1"`,
		acceptEncoding:     "gzip",
		rawQuery:           "X-Amz-Signature=secret",
	}, downloadRequest)
	assert.Equal(t, []codeArtifactRedirectEvent{
		codeArtifactRedirectSameOrigin,
		codeArtifactRedirectCrossOrigin,
	}, recorded.redirect)
}
