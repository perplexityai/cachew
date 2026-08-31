package strategy //nolint:testpackage // White-box coverage verifies metadata rewriting at the proxy boundary.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestCodeArtifactRewritesPackageMetadata(t *testing.T) {
	tests := []struct {
		name string
		path string
		body func(string) string
		want func(string) string
	}{
		{
			name: "npm tarball URL",
			path: "/npm/repository/package",
			body: func(origin string) string {
				return `{"versions":{"1.2.3":{"dist":{"tarball":"` + origin + `/npm/repository/package/-/package-1.2.3.tgz"}}}}`
			},
			want: func(proxy string) string {
				return `{"versions":{"1.2.3":{"dist":{"tarball":"` + proxy + `/npm/repository/package/-/package-1.2.3.tgz"}}}}`
			},
		},
		{
			name: "Cargo download template and anonymous access",
			path: "/cargo/repository/config.json",
			body: func(origin string) string {
				return `{"dl":"` + origin + `/cargo/repository/crates/{crate}/{version}","api":"` + origin + `/cargo/repository/-","auth-required":true}`
			},
			want: func(proxy string) string {
				return `{"dl":"` + proxy + `/cargo/repository/crates/{crate}/{version}","api":"` + proxy + `/cargo/repository/-","auth-required":false}`
			},
		},
		{
			name: "NuGet service resources",
			path: "/nuget/repository/v3/index.json",
			body: func(origin string) string {
				return `{"resources":[{"@id":"` + origin + `/nuget/repository/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg","@type":"PackageBaseAddress/3.0.0"}]}`
			},
			want: func(proxy string) string {
				return `{"resources":[{"@id":"` + proxy + `/nuget/repository/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg","@type":"PackageBaseAddress/3.0.0"}]}`
			},
		},
		{
			name: "Swift release URL",
			path: "/swift/repository/perplexity/design-tokens",
			body: func(origin string) string {
				return `{"releases":{"1.2.3":{"url":"` + origin + `/swift/repository/perplexity/design-tokens/1.2.3"}},"external":"https://example.com/release"}`
			},
			want: func(proxy string) string {
				return `{"releases":{"1.2.3":{"url":"` + proxy + `/swift/repository/perplexity/design-tokens/1.2.3"}},"external":"https://example.com/release"}`
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var originURL string
			var mu sync.Mutex
			observedHeaders := make(http.Header)
			origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				observedHeaders = r.Header.Clone()
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "identity")
				w.Header().Set("ETag", `"origin-metadata"`)
				w.Header().Set("Last-Modified", testCodeArtifactModified)
				_, _ = w.Write([]byte(test.body(originURL)))
			})
			mux, originServer, _, ctx := newTestCodeArtifact(
				t,
				origin,
				tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)},
			)
			originURL = originServer.URL
			proxyURL := "https://cachew.example.com/" + originServer.Listener.Addr().String()
			req := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, test.path), nil).WithContext(ctx)
			req.Header.Set("Accept-Encoding", "gzip")
			req.Header.Set("If-None-Match", `"old-metadata"`)
			req.Header.Set("Range", "bytes=0-10")
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assertJSONEqual(t, test.want(proxyURL), w.Body.String())
			assert.Equal(t, "", w.Header().Get("Content-Encoding"))
			assert.Equal(t, "", w.Header().Get("ETag"))
			assert.Equal(t, "", w.Header().Get("Last-Modified"))
			assert.Equal(t, strconv.Itoa(w.Body.Len()), w.Header().Get("Content-Length"))
			mu.Lock()
			headers := observedHeaders.Clone()
			mu.Unlock()
			assert.Equal(t, "", headers.Get("Accept-Encoding"))
			assert.Equal(t, "", headers.Get("If-None-Match"))
			assert.Equal(t, "", headers.Get("Range"))
		})
	}
}

func TestCodeArtifactStreamsExtensionlessSwiftArchive(t *testing.T) {
	const archive = "swift archive"
	var originURL string
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/swift/repository/perplexity/design-tokens":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"releases":{"1.2.3":{"url":"` + originURL + `/swift/repository/perplexity/design-tokens/1.2.3"}}}`))
		case "/swift/repository/perplexity/design-tokens/1.2.3":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte(archive))
		default:
			http.NotFound(w, r)
		}
	})
	mux, originServer, _, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)},
	)
	originURL = originServer.URL
	proxyURL := "https://cachew.example.com/" + originServer.Listener.Addr().String()

	metadata := httptest.NewRecorder()
	mux.ServeHTTP(metadata, httptest.NewRequest(
		http.MethodGet,
		codeArtifactPath(originServer, "/swift/repository/perplexity/design-tokens"),
		nil,
	).WithContext(ctx))
	assert.Equal(t, http.StatusOK, metadata.Code)
	assertJSONEqual(
		t,
		`{"releases":{"1.2.3":{"url":"`+proxyURL+`/swift/repository/perplexity/design-tokens/1.2.3"}}}`,
		metadata.Body.String(),
	)

	release := httptest.NewRecorder()
	mux.ServeHTTP(release, httptest.NewRequest(
		http.MethodGet,
		codeArtifactPath(originServer, "/swift/repository/perplexity/design-tokens/1.2.3"),
		nil,
	).WithContext(ctx))
	assert.Equal(t, http.StatusOK, release.Code)
	assert.Equal(t, "application/zip", release.Header().Get("Content-Type"))
	assert.Equal(t, archive, release.Body.String())
}

func TestCodeArtifactRejectsUnsafePackageMetadata(t *testing.T) {
	const originSecretURL = "https://codeartifact.example.com/private"
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "malformed JSON", contentType: "application/json", body: `{"url":"` + originSecretURL},
		{name: "unexpected content type", contentType: "text/plain", body: `{"url":"` + originSecretURL + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				_, _ = w.Write([]byte(test.body))
			})
			mux, originServer, _, ctx := newTestCodeArtifact(
				t,
				origin,
				tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)},
			)
			w := httptest.NewRecorder()

			mux.ServeHTTP(
				w,
				httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/npm/repository/package"), nil).WithContext(ctx),
			)

			assert.Equal(t, http.StatusBadGateway, w.Code)
			assert.False(t, strings.Contains(w.Body.String(), originSecretURL), "origin metadata must fail closed")
		})
	}
}

func TestCodeArtifactRewritesRedirectedCargoMetadata(t *testing.T) {
	type observedHeaders struct {
		acceptEncoding string
		ifNoneMatch    string
		rangeHeader    string
	}
	var observed observedHeaders
	var originURL string
	download := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = observedHeaders{
			acceptEncoding: r.Header.Get("Accept-Encoding"),
			ifNoneMatch:    r.Header.Get("If-None-Match"),
			rangeHeader:    r.Header.Get("Range"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"dl":"` + originURL + `/cargo/repository/crates/{crate}/{version}","auth-required":true}`))
	}))
	t.Cleanup(download.Close)
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, download.URL+"/signed-metadata", http.StatusFound)
	})
	mux, originServer, _, ctx := newTestCodeArtifact(
		t,
		origin,
		tokenResponse{token: "token", expiresAt: time.Now().Add(time.Hour)},
	)
	originURL = originServer.URL
	handler, _ := mux.Handler(httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/cargo/repository/config.json"), nil))
	strategy := handler.(*CodeArtifact)
	transport := download.Client().Transport.(*http.Transport).Clone()
	transport.DisableCompression = true
	strategy.client.Transport = transport
	req := httptest.NewRequest(http.MethodGet, codeArtifactPath(originServer, "/cargo/repository/config.json"), nil).WithContext(ctx)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("If-None-Match", `"metadata"`)
	req.Header.Set("Range", "bytes=0-10")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	proxyURL := "https://cachew.example.com/" + originServer.Listener.Addr().String()
	assertJSONEqual(t, `{"dl":"`+proxyURL+`/cargo/repository/crates/{crate}/{version}","auth-required":false}`, w.Body.String())
	assert.Equal(t, observedHeaders{}, observed)
}

func TestCodeArtifactValidatesProxyBaseURL(t *testing.T) {
	tests := []struct {
		name         string
		proxyBaseURL string
		wantError    string
	}{
		{
			name:      "required",
			wantError: "codeartifact: missing required configuration: proxy-base-url",
		},
		{
			name:         "HTTPS required",
			proxyBaseURL: "http://cachew.example.com",
			wantError:    "codeartifact: proxy-base-url must be an HTTPS origin",
		},
		{
			name:         "origin only",
			proxyBaseURL: "https://cachew.example.com/packages",
			wantError:    "codeartifact: proxy-base-url must not contain credentials, a path, query, or fragment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testCodeArtifactConfig("https://codeartifact.example.com")
			config.ProxyBaseURL = test.proxyBaseURL

			_, _, err := validateCodeArtifactConfig(config, false)

			assert.EqualError(t, err, test.wantError)
		})
	}
}

func assertJSONEqual(t *testing.T, want, got string) {
	t.Helper()
	var wantValue any
	assert.NoError(t, json.Unmarshal([]byte(want), &wantValue))
	var gotValue any
	assert.NoError(t, json.Unmarshal([]byte(got), &gotValue))
	assert.Equal(t, wantValue, gotValue)
}
