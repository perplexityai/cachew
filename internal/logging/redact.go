package logging

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/alecthomas/errors"
)

const redactedQuery = "REDACTED"

// RedactURL formats u without its password or query. Query strings can carry
// credentials, such as the signature of a presigned URL.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.RawQuery == "" {
		return u.Redacted()
	}
	redacted := *u
	redacted.RawQuery = redactedQuery
	return redacted.Redacted()
}

// RedactRequestURI removes the query from a request target such as
// [net/http.Request.RequestURI].
func RedactRequestURI(uri string) string {
	path, _, found := strings.Cut(uri, "?")
	if !found {
		return uri
	}
	return path + "?" + redactedQuery
}

// RedactText removes the query of every absolute HTTP(S) URL in text, such as
// the URL that a failed [net/http.Client] request puts in its error. A query
// may be %q-escaped, as it is in a [url.Error].
func RedactText(text string) string {
	if !strings.Contains(text, "?") {
		return text
	}
	var out strings.Builder
	for {
		start := urlStart(text)
		if start < 0 {
			break
		}
		query := start + strings.IndexAny(text[start:], "?#\\\"'<> \t\r\n")
		if query < start || text[query] != '?' {
			// No query: keep the scheme and look for the next URL after it.
			next := start + len("http")
			out.WriteString(text[:next])
			text = text[next:]
			continue
		}
		end := query + 1
		for end < len(text) && !strings.ContainsRune("\"'<> \t\r\n", rune(text[end])) {
			if text[end] == '\\' && end+1 < len(text) {
				end++
			}
			end++
		}
		out.WriteString(text[:query+1])
		out.WriteString(redactedQuery)
		text = text[end:]
	}
	out.WriteString(text)
	return out.String()
}

// urlStart returns the index of the first "http://" or "https://" in text,
// in any letter case, or -1.
func urlStart(text string) int {
	for offset := 0; ; {
		i := strings.Index(text[offset:], "://")
		if i < 0 {
			return -1
		}
		i += offset
		for _, scheme := range []string{"https", "http"} {
			if start := i - len(scheme); start >= 0 && strings.EqualFold(text[start:i], scheme) {
				return start
			}
		}
		offset = i + len("://")
	}
}

// redactingHandler keeps URL queries out of log records, wherever in the
// message or attributes they appear.
type redactingHandler struct {
	inner slog.Handler
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	redacted := slog.NewRecord(r.Time, r.Level, RedactText(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		redacted.AddAttrs(redactAttr(a))
		return true
	})
	return errors.Wrap(h.inner.Handle(ctx, redacted), "handle log record")
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &redactingHandler{inner: h.inner.WithAttrs(redacted)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindString {
		a.Value = slog.StringValue(RedactText(a.Value.String()))
		return a
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		redacted := make([]slog.Attr, len(group))
		for i, member := range group {
			redacted[i] = redactAttr(member)
		}
		a.Value = slog.GroupValue(redacted...)
		return a
	}
	if a.Value.Kind() != slog.KindAny {
		return a
	}
	switch v := a.Value.Any().(type) {
	case *url.URL:
		a.Value = slog.StringValue(RedactURL(v))
	case url.URL:
		a.Value = slog.StringValue(RedactURL(&v))
	case error:
		a.Value = slog.StringValue(RedactText(v.Error()))
	}
	return a
}
