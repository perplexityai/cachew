package strategy

import (
	"strconv"
	"strings"
)

type codeArtifactGoAwayDetails struct {
	code         string
	lastStreamID uint32
}

func codeArtifactGoAway(err error) (codeArtifactGoAwayDetails, bool) {
	remaining := 32
	return codeArtifactFindGoAway(err, &remaining)
}

func codeArtifactFindGoAway(err error, remaining *int) (codeArtifactGoAwayDetails, bool) {
	if *remaining == 0 {
		return codeArtifactGoAwayDetails{}, false
	}
	*remaining--
	if err == nil {
		return codeArtifactGoAwayDetails{}, false
	}
	switch wrapped := err.(type) { //nolint:errorlint // Inspect unwrap methods without unbounded errors.As traversal.
	case interface{ Unwrap() error }:
		if inner := wrapped.Unwrap(); inner != nil {
			return codeArtifactFindGoAway(inner, remaining)
		}
	case interface{ Unwrap() []error }:
		for _, inner := range wrapped.Unwrap() {
			if details, ok := codeArtifactFindGoAway(inner, remaining); ok {
				return details, true
			}
			if *remaining == 0 {
				break
			}
		}
		return codeArtifactGoAwayDetails{}, false
	}
	return parseCodeArtifactGoAway(err.Error())
}

// net/http's bundled HTTP/2 transport exposes an unexported GOAWAY error type.
// Parse only its bounded metadata prefix, never retaining peer-controlled debug
// data or wrapper text (which can contain credential-bearing URLs).
func parseCodeArtifactGoAway(message string) (codeArtifactGoAwayDetails, bool) {
	const (
		prefix      = "http2: server sent GOAWAY and closed the connection; LastStreamID="
		codePrefix  = ", ErrCode="
		debugPrefix = ", debug=\""
	)
	header, ok := strings.CutPrefix(message[:min(len(message), 128)], prefix)
	if !ok {
		return codeArtifactGoAwayDetails{}, false
	}
	streamID, rest, ok := strings.Cut(header, codePrefix)
	if !ok {
		return codeArtifactGoAwayDetails{}, false
	}
	code, _, ok := strings.Cut(rest, debugPrefix)
	minimumLength := len(prefix) + len(streamID) + len(codePrefix) + len(code) + len(debugPrefix) + 1
	if !ok || len(message) < minimumLength || !strings.HasSuffix(message, "\"") {
		return codeArtifactGoAwayDetails{}, false
	}
	id, err := strconv.ParseUint(streamID, 10, 31)
	if err != nil || strconv.FormatUint(id, 10) != streamID {
		return codeArtifactGoAwayDetails{}, false
	}
	switch code {
	case "NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR",
		"SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM",
		"CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM",
		"INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED":
		return codeArtifactGoAwayDetails{code: strings.Clone(code), lastStreamID: uint32(id)}, true
	default:
		return codeArtifactGoAwayDetails{}, false
	}
}
