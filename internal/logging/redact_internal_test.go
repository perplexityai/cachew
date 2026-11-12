package logging

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

const signedQuery = "X-Amz-Credential=synthetic-credential&X-Amz-Signature=synthetic-signature"

func TestRedactText(t *testing.T) {
	tests := map[string]struct{ text, want string }{
		"NoURL":       {text: "is the cache warm?", want: "is the cache warm?"},
		"NoQuery":     {text: "GET https://example.invalid/a failed", want: "GET https://example.invalid/a failed"},
		"Query":       {text: "https://example.invalid/a?" + signedQuery, want: "https://example.invalid/a?REDACTED"},
		"UpperScheme": {text: "HTTP://example.invalid?" + signedQuery, want: "HTTP://example.invalid?REDACTED"},
		"Fragment":    {text: "https://example.invalid/a#b?c", want: "https://example.invalid/a#b?c"},
		"Several": {
			text: "https://one.invalid/a?" + signedQuery + " then http://two.invalid/ and https://three.invalid/c?" + signedQuery + ".",
			want: "https://one.invalid/a?REDACTED then http://two.invalid/ and https://three.invalid/c?REDACTED",
		},
		"NestedClientErrors": {
			text: errors.Wrap(&url.Error{Op: "Get", URL: "https://one.invalid/a?" + signedQuery,
				Err: &url.Error{Op: "Get", URL: "https://two.invalid/b?" + signedQuery, Err: http.ErrHandlerTimeout}}, "failed to fetch").Error(),
			want: `failed to fetch: Get "https://one.invalid/a?REDACTED": Get "https://two.invalid/b?REDACTED": ` + http.ErrHandlerTimeout.Error(),
		},
		"QuotedQueryWithEscapes": {
			text: (&url.Error{Op: "Get", URL: `https://example.invalid/a?sig="synthetic-signature"&next=1`, Err: http.ErrHandlerTimeout}).Error(),
			want: `Get "https://example.invalid/a?REDACTED": ` + http.ErrHandlerTimeout.Error(),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, RedactText(test.text))
		})
	}
}

func TestRedactURL(t *testing.T) {
	tests := map[string]string{
		"/bucket/object":                                 "/bucket/object",
		"/bucket/object?" + signedQuery:                  "/bucket/object?REDACTED",
		"https://user:secret@example.invalid/a?token=1":  "https://user:xxxxx@example.invalid/a?REDACTED",
		"https://example.invalid/a%2Fb?" + signedQuery:   "https://example.invalid/a%2Fb?REDACTED",
		"https://example.invalid/a?" + signedQuery + "#": "https://example.invalid/a?REDACTED",
	}
	for raw, want := range tests {
		u, err := url.Parse(raw)
		assert.NoError(t, err)
		assert.Equal(t, want, RedactURL(u))
	}
	assert.Equal(t, "", RedactURL(nil))
	assert.Equal(t, "/a?REDACTED", RedactRequestURI("/a?"+signedQuery))
	assert.Equal(t, "/a", RedactRequestURI("/a"))
}

type logValuer struct{ u *url.URL }

func (v logValuer) LogValue() slog.Value { return slog.AnyValue(v.u) }

func TestRedactingHandler(t *testing.T) {
	signed, err := url.Parse("https://example.invalid/object?" + signedQuery)
	assert.NoError(t, err)
	clientErr := errors.Wrap(&url.Error{Op: "Get", URL: signed.String(), Err: http.ErrHandlerTimeout}, "failed to fetch")

	for _, json := range []bool{false, true} {
		var logs bytes.Buffer
		var inner slog.Handler = slog.NewTextHandler(&logs, nil)
		if json {
			inner = &messageHandler{inner: slog.NewJSONHandler(&logs, nil)}
		}
		logger := slog.New(&redactingHandler{inner: inner}).With("bound", signed).WithGroup("request")
		logger.ErrorContext(context.Background(), "Fetch of "+signed.String()+" failed",
			"error", clientErr,
			"pointer", signed,
			"value", *signed,
			"text", signed.String(),
			"valuer", logValuer{signed},
			slog.Group("nested", slog.Any("error", clientErr), slog.Int("status", http.StatusBadGateway)),
		)

		assert.NotContains(t, logs.String(), "synthetic")
		assert.NotContains(t, logs.String(), "X-Amz")
		// Every URL is still identifiable, and unrelated attributes are untouched.
		assert.True(t, bytes.Count(logs.Bytes(), []byte("https://example.invalid/object?REDACTED")) >= 8, logs.String())
		assert.Contains(t, logs.String(), "502")
		assert.Contains(t, logs.String(), http.ErrHandlerTimeout.Error())
	}
}

func TestConfigureRedactsURLQueries(t *testing.T) {
	for _, json := range []bool{false, true} {
		logger, _ := Configure(context.Background(), Config{JSON: json})
		_, ok := logger.Handler().(*redactingHandler)
		assert.True(t, ok)
	}
}
