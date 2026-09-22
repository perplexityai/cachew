package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/packageaudit"
)

func TestPackageAuditConfigIsOptIn(t *testing.T) {
	for _, test := range []struct {
		input   string
		enabled bool
		invalid bool
	}{
		{},
		{input: `package-audit { directory = "/var/log/cachew/audit" }`, enabled: true},
		{input: `package-audit { directory = "/var/log/cachew/audit" exclude-purls = ["pkg:npm/@private/*"] }`, enabled: true},
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

func TestGracefulShutdownDrainsAuditAfterHTTP(t *testing.T) {
	for _, delay := range []time.Duration{0, 650 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) { testGracefulShutdownDrainsAuditAfterHTTP(t, delay) })
	}
}

func testGracefulShutdownDrainsAuditAfterHTTP(t *testing.T, delay time.Duration) {
	const purl = "pkg:npm/shutdown-test@1.0.0"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	directory := filepath.Join(t.TempDir(), "audit")
	sink, err := packageaudit.New(packageaudit.Config{Directory: directory}, logger.Warn)
	assert.NoError(t, err)
	ctx, cancel := context.WithCancel(packageaudit.ContextWithSink(t.Context(), sink))
	cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		sink.Record(packageaudit.Event{PURL: purl})
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	requestDone := startAuditShutdownRequest(t, server.URL)
	<-entered
	shutdownStarted, shutdownDone := make(chan struct{}), make(chan struct{})
	var shutdownOnce sync.Once
	server.Config.RegisterOnShutdown(func() { shutdownOnce.Do(func() { close(shutdownStarted) }) })
	var shuttingDown atomic.Bool
	go func() {
		gracefulShutdown(ctx, logger, server.Config, &shuttingDown, 0, time.Second)
		close(shutdownDone)
	}()
	<-shutdownStarted
	time.Sleep(delay)
	releaseOnce.Do(func() { close(release) })
	<-shutdownDone
	assert.NoError(t, <-requestDone)
	assert.True(t, shuttingDown.Load())
	files, err := filepath.Glob(filepath.Join(directory, "*.ndjson"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(files))
	data, err := os.ReadFile(files[0])
	assert.NoError(t, err)
	var event packageaudit.Event
	assert.NoError(t, json.Unmarshal(data, &event))
	assert.Equal(t, purl, event.PURL)
	reopened, err := packageaudit.New(packageaudit.Config{Directory: directory}, logger.Warn)
	assert.NoError(t, err)
	assert.NoError(t, reopened.Close(t.Context()))
}

func TestGracefulShutdownBoundsBlockedHandlers(t *testing.T) {
	const shutdownTimeout = time.Second
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("audit=%t", enabled), func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			ctx := t.Context()
			if enabled {
				sink, err := packageaudit.New(packageaudit.Config{Directory: filepath.Join(t.TempDir(), "audit")}, logger.Warn)
				assert.NoError(t, err)
				ctx = packageaudit.ContextWithSink(ctx, sink)
			}
			entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
					<-release
				case <-release:
				}
			}))
			t.Cleanup(server.Close)
			requestDone := startAuditShutdownRequest(t, server.URL)
			t.Cleanup(func() {
				close(release)
				<-requestDone
			})
			<-entered
			var shuttingDown atomic.Bool
			start := time.Now()
			gracefulShutdown(ctx, logger, server.Config, &shuttingDown, 0, shutdownTimeout)
			elapsed := time.Since(start)
			assert.True(t, elapsed >= shutdownTimeout)
			assert.True(t, elapsed < 2*shutdownTimeout)
			if enabled {
				select {
				case <-canceled:
				case <-time.After(time.Second):
					t.Fatal("shutdown did not cancel the blocked request before handler release")
				}
			}
		})
	}
}

func startAuditShutdownRequest(t *testing.T, url string) <-chan error {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	assert.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			err = response.Body.Close()
		}
		done <- err
	}()
	return done
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
