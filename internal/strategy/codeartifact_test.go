package strategy //nolint:testpackage // White-box coverage is required for token and transport injection.

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"

	"github.com/block/cachew/internal/logging"
)

const (
	testCodeArtifactDomain      = "example"
	testCodeArtifactDomainOwner = "123456789012"
	testCodeArtifactRegion      = "us-east-1"
	testCodeArtifactRoleARN     = "arn:aws:iam::123456789012:role/cachew-reader"
)

type tokenResponse struct {
	token     string
	expiresAt time.Time
	status    int
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
		Target:      target,
		Domain:      testCodeArtifactDomain,
		DomainOwner: testCodeArtifactDomainOwner,
		Region:      testCodeArtifactRegion,
		RoleARN:     testCodeArtifactRoleARN,
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
	_, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), true)
	assert.NoError(t, err)
	return mux, originServer, tokenServer, ctx
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

func TestCodeArtifactPreservesHEADWithoutBody(t *testing.T) {
	var method string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
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
	assert.Equal(t, "123", w.Header().Get("Content-Length"))
	assert.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", w.Header().Get("Last-Modified"))
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

func TestCodeArtifactRefreshesBeforeExpiration(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "near-expiry", expiresAt: now.Add(time.Minute)},
		tokenResponse{token: "fresh", expiresAt: now.Add(time.Hour)},
	)
	manager := tokenServer.tokenManager(func() time.Time { return now })

	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	second, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)

	assert.Equal(t, "near-expiry", first.value)
	assert.Equal(t, "fresh", second.value)
	assert.Equal(t, 2, tokenServer.requestCount())
}

func TestCodeArtifactRefreshFailureFallsBackOnlyToUnrejectedToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tokenServer := newLocalTokenServer(
		t,
		tokenResponse{token: "near-expiry", expiresAt: now.Add(time.Minute)},
		tokenResponse{status: http.StatusServiceUnavailable},
	)
	manager := tokenServer.tokenManager(func() time.Time { return now })

	first, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	fallback, err := manager.Token(t.Context(), 0)
	assert.NoError(t, err)
	assert.Equal(t, first, fallback)

	_, err = manager.Token(t.Context(), first.generation)
	assert.Error(t, err)
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
	strategy, err := newCodeArtifact(ctx, testCodeArtifactConfig(originServer.URL), mux, tokenServer.tokenManager(time.Now), true)
	assert.NoError(t, err)
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
}
