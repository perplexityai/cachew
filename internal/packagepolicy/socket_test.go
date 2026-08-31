package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

const (
	testOrganization = "example-org"
	testToken        = "socket-test-token"
	testPURL         = "pkg:npm/chromatitle-js@1.0.0"
)

func TestNewSelectsSocketProvider(t *testing.T) {
	evaluator, err := New(Config{Socket: &SocketConfig{Organization: testOrganization, Token: testToken}})
	assert.NoError(t, err)
	assert.NotZero(t, evaluator)

	_, err = New(Config{})
	assert.Error(t, err)
}

func TestClientEvaluatesOrganizationPolicy(t *testing.T) {
	tests := []struct {
		name     string
		response string
		verdict  Verdict
		reasons  []string
	}{
		{
			name:     "allows policy-approved package",
			response: `{"type":"npm","name":"lodash","version":"4.17.21","alerts":[{"type":"unpopularPackage","action":"monitor"}]}`,
			verdict:  VerdictAllow,
		},
		{
			name:     "denies policy error",
			response: `{"type":"npm","name":"chromatitle-js","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`,
			verdict:  VerdictDeny,
			reasons:  []string{"malware"},
		},
		{
			name:     "waits for pending analysis",
			response: `{"type":"npm","name":"new-package","version":"1.0.0","alerts":[{"type":"pendingScan","action":"ignore"}]}`,
			verdict:  VerdictPending,
			reasons:  []string{"pendingScan"},
		},
		{
			name:     "denies unscanned package",
			response: `{"type":"npm","name":"unknown-package","version":"1.0.0","alerts":[{"type":"notFound","action":"ignore"}]}`,
			verdict:  VerdictDeny,
			reasons:  []string{"notFound"},
		},
		{
			name: "denies if any package artifact is blocked",
			response: `{"type":"pypi","name":"example","version":"1.0.0","release":"py3-none-any-whl","alerts":[]}
{"type":"pypi","name":"example","version":"1.0.0","release":"tar-gz","alerts":[{"type":"malware","action":"error"}]}`,
			verdict: VerdictDeny,
			reasons: []string{"malware"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/v0/orgs/example-org/purl", r.URL.Path)
				assert.Equal(t, "Bearer "+testToken, r.Header.Get("Authorization"))
				assert.Equal(t, "true", r.URL.Query().Get("alerts"))
				assert.Equal(t, "true", r.URL.Query().Get("compact"))
				assert.Equal(t, "true", r.URL.Query().Get("poll"))
				assert.Equal(t, "false", r.URL.Query().Get("purlErrors"))
				assert.Equal(t, "30", r.URL.Query().Get("timeoutSec"))

				var body struct {
					Components []struct {
						PURL string `json:"purl"`
					} `json:"components"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Equal(t, testPURL, body.Components[0].PURL)
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = w.Write([]byte(test.response + "\n"))
			}))
			t.Cleanup(server.Close)

			client, err := newSocketEvaluator(SocketConfig{
				APIURL:       server.URL,
				Organization: testOrganization,
				Token:        testToken,
				Timeout:      30 * time.Second,
			}, true)
			assert.NoError(t, err)

			decision, err := client.Evaluate(context.Background(), testPURL)
			assert.NoError(t, err)
			assert.Equal(t, test.verdict, decision.Verdict)
			assert.Equal(t, test.reasons, decision.Reasons)
		})
	}
}

func TestClientFailsClosedOnInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
	}{
		{name: "upstream failure", statusCode: http.StatusTooManyRequests},
		{name: "malformed stream", statusCode: http.StatusOK, response: `{"type":`},
		{name: "empty stream", statusCode: http.StatusOK},
		{name: "unknown policy action", statusCode: http.StatusOK, response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"future-action"}]}`},
		{name: "mismatched PURL", statusCode: http.StatusOK, response: `{"inputPurl":"pkg:npm/other@1.0.0","type":"npm","name":"other","version":"1.0.0","alerts":[]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.response))
			}))
			t.Cleanup(server.Close)
			client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
			assert.NoError(t, err)

			_, err = client.Evaluate(context.Background(), testPURL)
			assert.Error(t, err)
		})
	}
}

func TestClientDoesNotForwardTokenAcrossRedirects(t *testing.T) {
	redirectRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectRequests++
		_, _ = w.Write([]byte(`{"type":"npm","name":"example","version":"1.0.0","alerts":[]}`))
	}))
	t.Cleanup(target.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)

	_, err = client.Evaluate(context.Background(), testPURL)
	assert.Error(t, err)
	assert.Equal(t, 0, redirectRequests)
}
