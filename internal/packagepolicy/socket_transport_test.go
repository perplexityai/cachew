package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

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
			name:     "treats unscanned package as pending",
			response: `{"type":"npm","name":"unknown-package","version":"1.0.0","alerts":[{"type":"notFound","action":"ignore"}]}`,
			verdict:  VerdictPending,
			reasons:  []string{"notFound"},
		},
		{
			name: "denies if any package artifact is blocked",
			response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[]}
{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`,
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
				assert.False(t, r.URL.Query().Has("labels"))

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

func TestClientReportsInvalidResponsesAsErrors(t *testing.T) {
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

func TestClientPreservesTransportFailureForCallerLogging(t *testing.T) {
	transportErr := errors.New("dial Socket API")
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	client.httpClient.Transport = roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, transportErr
	})

	_, err = client.Evaluate(context.Background(), testPURL)
	assert.True(t, errors.Is(err, transportErr))
}

func TestClientPreservesErrorResponseReadFailure(t *testing.T) {
	readErr := errors.New("read Socket error response")
	client, err := newSocketEvaluator(SocketConfig{
		APIURL:       "https://socket.example.com",
		Organization: testOrganization,
		Token:        testToken,
	}, false)
	assert.NoError(t, err)
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Status:     http.StatusText(http.StatusTooManyRequests),
			Header:     make(http.Header),
			Body:       io.NopCloser(iotest.ErrReader(readErr)),
		}, nil
	})

	_, err = client.Evaluate(context.Background(), testPURL)
	assert.True(t, errors.Is(err, readErr))
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

func TestClientAcceptsPercentDecodedInputPURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"inputPurl":"pkg:npm/@ctrl/tinycolor@4.1.1","type":"npm","name":"@ctrl/tinycolor","version":"4.1.1","alerts":[]}`)
	}))
	t.Cleanup(server.Close)
	client, err := newSocketEvaluator(SocketConfig{APIURL: server.URL, Organization: testOrganization, Token: testToken}, true)
	assert.NoError(t, err)

	decision, err := client.Evaluate(t.Context(), "pkg:npm/%40ctrl/tinycolor@4.1.1")
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
}

func TestClientUsesPolicyLabel(t *testing.T) {
	const label = "cachew-audit"
	client, err := newSocketEvaluator(SocketConfig{
		APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken, Label: label,
	}, false)
	assert.NoError(t, err)
	client.httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, label, r.URL.Query().Get("labels"))
		assert.Equal(t, "1", r.URL.Query().Get("timeoutSec"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(testAllowResponse)),
		}, nil
	})
	decision, err := client.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictAllow, decision.Verdict)
}

func TestSocketTimeoutValidation(t *testing.T) {
	for _, test := range []struct {
		timeout    time.Duration
		budget     time.Duration
		timeoutSec int
	}{
		{0, 200 * time.Millisecond, 1},
		{time.Nanosecond, time.Nanosecond, 1},
		{200 * time.Millisecond, 200 * time.Millisecond, 1},
		{350 * time.Millisecond, 350 * time.Millisecond, 1},
		{1500 * time.Millisecond, 1500 * time.Millisecond, 2},
		{20 * time.Minute, 20 * time.Minute, 1200},
	} {
		t.Run(test.timeout.String(), func(t *testing.T) {
			client, err := newSocketEvaluator(SocketConfig{
				APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
				Timeout: test.timeout,
			}, false)
			assert.NoError(t, err)
			assert.Equal(t, test.budget, client.httpClient.Timeout)
			assert.Equal(t, test.timeoutSec, client.timeoutSec)
		})
	}
	for _, timeout := range []time.Duration{-time.Nanosecond, 20*time.Minute + time.Nanosecond} {
		_, err := newSocketEvaluator(SocketConfig{
			APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
			Timeout: timeout,
		}, false)
		assert.Error(t, err)
	}
}

func TestSocketQueueTimeoutValidation(t *testing.T) {
	config := SocketConfig{APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken}
	client, err := newSocketEvaluator(config, false)
	assert.NoError(t, err)
	assert.Equal(t, defaultQueueTimeout, client.queueTimeout)
	config.QueueTimeout = -time.Second
	_, err = newSocketEvaluator(config, false)
	assert.Error(t, err)
}

func TestClientPreservesDenialAtResponseLimit(t *testing.T) {
	client, err := newSocketEvaluator(SocketConfig{
		APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
	}, false)
	assert.NoError(t, err)
	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		response := strings.Repeat("\n", maxResponseBytes-len(testDenyResponse)) + testDenyResponse + "\nextra"
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	decision, err := client.Evaluate(t.Context(), testPURL)
	assert.NoError(t, err)
	assert.Equal(t, VerdictDeny, decision.Verdict)
}

func TestSocketRejectsNonSlugLabel(t *testing.T) {
	config := SocketConfig{APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken}
	config.Label = "cachew_rollout.v2"
	_, err := newSocketEvaluator(config, false)
	assert.NoError(t, err)

	for _, label := range []string{"cachew,other", "cachew rollout", "-cachew"} {
		config.Label = label
		_, err := newSocketEvaluator(config, false)
		assert.Error(t, err)
	}
}
