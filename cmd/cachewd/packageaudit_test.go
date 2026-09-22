package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"
)

func TestPackageAuditConfigIsOptIn(t *testing.T) {
	for _, test := range []struct {
		input   string
		enabled bool
		invalid bool
	}{
		{},
		{input: `package-audit { directory = "/var/log/cachew/audit" }`, enabled: true},
		{input: `package-audit {}`, invalid: true},
		{input: `package-audit { directory = "" }`, invalid: true},
	} {
		ast, err := hcl.Parse(strings.NewReader(test.input + "\nlog { level = \"info\" }"))
		assert.NoError(t, err)
		config, _, err := loadGlobalConfig(ast)
		if test.invalid {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
		if !test.invalid {
			assert.Equal(t, test.enabled, config.PackageAudit != nil)
		}
	}
}

func TestPackageAuditSchemaDoesNotOpenSink(t *testing.T) {
	const helperConfigEnv = "CACHEW_TEST_PACKAGE_AUDIT_SCHEMA_CONFIG"
	if config := os.Getenv(helperConfigEnv); config != "" {
		os.Args = []string{"cachewd", "--config", config, "--schema"} //nolint:reassign // Only the isolated helper process runs the CLI.
		main()
		return
	}
	directory := t.TempDir()
	auditDirectory := filepath.Join(directory, "must-not-exist")
	configPath := filepath.Join(directory, "cachew.hcl")
	contents := fmt.Sprintf("log { level = \"info\" }\npackage-audit { directory = %q }\n", auditDirectory)
	assert.NoError(t, os.WriteFile(configPath, []byte(contents), 0600))
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPackageAuditSchemaDoesNotOpenSink$")
	command.Env = append(os.Environ(), helperConfigEnv+"="+configPath, "OTEL_EXPORTER_OTLP_ENDPOINT=")
	output, err := command.CombinedOutput()
	assert.NoError(t, err, "%s", output)
	assert.True(t, strings.Contains(string(output), "package-audit"))
	_, err = os.Stat(auditDirectory)
	assert.True(t, os.IsNotExist(err))
}
