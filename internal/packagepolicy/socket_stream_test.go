package packagepolicy //nolint:testpackage // White-box coverage is required for HTTP transport injection.

import (
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestDenyDominatesInvalidStreamData(t *testing.T) {
	denied := `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"error"}]}`
	tests := []struct {
		name     string
		response string
	}{
		{name: "malformed record", response: denied + "\n" + `{"type":`},
		{name: "preceding malformed record", response: `{"type":` + "\n" + denied},
		{name: "preceding unsupported record", response: `{"_type":"future"}` + "\n" + denied},
		{name: "preceding unknown action", response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"other","action":"future"}]}` + "\n" + denied},
		{name: "unknown action record", response: denied + "\n" + `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"other","action":"future"}]}`},
		{name: "unknown action in denied record", response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"malware","action":"error"},{"type":"other","action":"future"}]}`},
		{name: "denial follows unknown action", response: `{"type":"npm","name":"example","version":"1.0.0","alerts":[{"type":"other","action":"future"},{"type":"malware","action":"error"}]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluateStream(strings.NewReader(test.response), testPURL)
			assert.NoError(t, err)
			assert.Equal(t, VerdictDeny, decision.Verdict)
			assert.Equal(t, []string{"malware"}, decision.Reasons)
		})
	}
}

func TestStreamPreservesErrorUnlessAnyRecordDenies(t *testing.T) {
	for _, invalid := range []string{`{"type":`, `{"_type":"future"}`} {
		_, firstErr := evaluateStream(strings.NewReader(invalid), testPURL)
		assert.Error(t, firstErr)
		_, err := evaluateStream(strings.NewReader(invalid+"\n"+testAllowResponse), testPURL)
		assert.Error(t, err)
		assert.Equal(t, firstErr.Error(), err.Error())
	}
}
