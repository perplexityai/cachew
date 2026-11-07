//go:build integration

package strategy //nolint:testpackage // Run an actual resolver through the real CodeArtifact strategy.

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func (o *goAwayOrigin) recover() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = 0
}

func codeArtifactUVExecutable(t *testing.T) string {
	t.Helper()
	executable := os.Getenv("CACHEW_TEST_UV")
	if executable == "" {
		var err error
		executable, err = exec.LookPath("uv")
		if err != nil {
			t.Fatal("integration tests require uv 0.13.4 on PATH or CACHEW_TEST_UV pointing to that executable")
		}
	}
	absolute, err := filepath.Abs(executable)
	assert.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, absolute, "--version").CombinedOutput()
	assert.NoError(t, err, "cannot run pinned uv executable: %s", output)
	version := strings.Fields(string(output))
	if len(version) < 2 || version[0] != "uv" || version[1] != "0.13.4" {
		t.Fatalf("integration tests require uv 0.13.4, got %q from %s", strings.TrimSpace(string(output)), absolute)
	}
	return absolute
}

type codeArtifactUVResult struct {
	stdout string
	stderr string
	err    error
}

func compileCodeArtifactUV(t *testing.T, ctx context.Context, executable string, proxy *goAwayProxy) codeArtifactUVResult {
	t.Helper()
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable,
		"--no-config", "pip", "compile", "-",
		"--default-index", proxy.server.URL+proxy.prefix+"/pypi/repository/simple/",
		"--python-version", "3.12", "--python-platform", "x86_64-unknown-linux-gnu",
		"--no-python-downloads", "--only-binary", ":all:",
		"--no-header", "--no-annotate", "--no-progress", "--color", "never",
	)
	command.Dir = home
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"UV_CACHE_DIR=" + filepath.Join(home, "uv-cache"),
		"UV_PYTHON_DOWNLOADS=never",
		"HTTP_PROXY=http://127.0.0.1:1",
		"HTTPS_PROXY=http://127.0.0.1:1",
		"NO_PROXY=127.0.0.1,localhost",
	}
	certificate := filepath.Join(home, "fixture-ca.pem")
	assert.NoError(t, os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: proxy.ca,
	}), 0o600))
	command.Env = append(command.Env, "SSL_CERT_FILE="+certificate)
	command.Stdin = strings.NewReader("cachew-goaway\n")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("uv exceeded the bounded test deadline: %v\n%s", ctx.Err(), stderr.String())
	}
	return codeArtifactUVResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func assertCodeArtifactUVResolved(t *testing.T, result codeArtifactUVResult) {
	t.Helper()
	assert.NoError(t, result.err, "uv failed to resolve the fixture package:\n%s", result.stderr)
	assert.Equal(t, "cachew-goaway==1.2.3\n", result.stdout)
}

func assertCodeArtifactUVRequests(t *testing.T, proxy *goAwayProxy, paths ...string) {
	t.Helper()
	expectedProtocol := 1
	if proxy.server.EnableHTTP2 {
		expectedProtocol = 2
	}
	for _, path := range paths {
		assert.Equal(t, expectedProtocol, proxy.wait(t, path), "uv must exercise the expected downstream protocol")
	}
}

func TestCodeArtifactUVGoAwayRecovery(t *testing.T) {
	executable := codeArtifactUVExecutable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	for _, downstream := range []string{"http1", "http2"} {
		t.Run(downstream, func(t *testing.T) {
			origin := newGoAwayOrigin(t, 1)
			proxy := newGoAwayProxy(t, origin, downstream)

			assertCodeArtifactUVResolved(t, compileCodeArtifactUV(t, ctx, executable, proxy))
			assertCodeArtifactUVRequests(t, proxy, goAwayIndexPath, goAwayIndexPath, goAwayWheelPath+".metadata")
			requests := origin.snapshot()
			assert.Equal(t, 3, len(requests))
			assert.Equal(t, goAwayOriginRequest{path: goAwayIndexPath, streamID: 1, failed: true}, requests[0])
			assert.Equal(t, goAwayOriginRequest{path: goAwayIndexPath, streamID: 1}, requests[1])
			assert.Equal(t, goAwayWheelPath+".metadata", requests[2].path)
			assertGoAwayDiagnostics(t, proxy, origin, 1)

			assertCodeArtifactUVResolved(t, compileCodeArtifactUV(t, ctx, executable, proxy))
			assertCodeArtifactUVRequests(t, proxy, goAwayIndexPath, goAwayWheelPath+".metadata")
			assert.Equal(t, requests, origin.snapshot(), "fresh uv cache must use the complete Cachew index and metadata fills")
		})
	}
}

func TestCodeArtifactUVGoAwayRetryExhaustion(t *testing.T) {
	executable := codeArtifactUVExecutable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	for _, downstream := range []string{"http1", "http2"} {
		t.Run(downstream, func(t *testing.T) {
			origin := newGoAwayOrigin(t, 100)
			proxy := newGoAwayProxy(t, origin, downstream)

			failure := compileCodeArtifactUV(t, ctx, executable, proxy)
			assert.Error(t, failure.err, "repeated origin truncation must fail resolution")
			assert.Equal(t, "", failure.stdout, "failed resolution must not emit a successful lock")
			for range 4 {
				assertCodeArtifactUVRequests(t, proxy, goAwayIndexPath)
			}
			requests := origin.snapshot()
			assert.Equal(t, 4, len(requests), "uv's default three retries must terminate after four failed attempts")
			for _, request := range requests {
				assert.Equal(t, goAwayIndexPath, request.path)
				assert.True(t, request.failed)
			}
			assertGoAwayDiagnostics(t, proxy, origin, 4)

			origin.recover()
			assertCodeArtifactUVResolved(t, compileCodeArtifactUV(t, ctx, executable, proxy))
			assertCodeArtifactUVRequests(t, proxy, goAwayIndexPath, goAwayWheelPath+".metadata")
			requests = origin.snapshot()
			assert.Equal(t, 6, len(requests), "recovery must fetch a fresh index and metadata, not a partial cached response")
			assert.Equal(t, goAwayIndexPath, requests[4].path)
			assert.False(t, requests[4].failed)
			assert.Equal(t, goAwayWheelPath+".metadata", requests[5].path)

			assertCodeArtifactUVResolved(t, compileCodeArtifactUV(t, ctx, executable, proxy))
			assertCodeArtifactUVRequests(t, proxy, goAwayIndexPath, goAwayWheelPath+".metadata")
			assert.Equal(t, requests, origin.snapshot(), "only the complete recovery response may be a warm Cachew hit")
		})
	}
}
