package tracing_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/block/cachew/internal/tracing"
)

// New is a no-op when disabled and must return a non-nil stop function.
func TestNewDisabled(t *testing.T) {
	stop, err := tracing.New(context.Background(), tracing.Config{Enabled: false})
	if err != nil {
		t.Fatalf("New(disabled) returned error: %v", err)
	}
	if stop == nil {
		t.Fatal("New(disabled) returned nil stop func")
	}
	stop()
}

func TestNewExportsHTTPTraces(t *testing.T) {
	for _, test := range []struct {
		name           string
		protocol       string
		tracesProtocol string
	}{
		{name: "general protocol", protocol: "http/protobuf"},
		{name: "traces protocol takes precedence", protocol: "grpc", tracesProtocol: "http/protobuf"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || len(body) == 0 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requests <- r.URL.Path
				w.Header().Set("Content-Type", "application/x-protobuf")
			}))
			defer server.Close()
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", test.protocol)
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", test.tracesProtocol)
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL+"/v1/traces")
			t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "1000")

			previous := otel.GetTracerProvider()
			defer otel.SetTracerProvider(previous)
			stop, err := tracing.New(context.Background(), tracing.Config{Enabled: true})
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}
			_, span := otel.Tracer("cachew-test").Start(context.Background(), "restore")
			span.End()
			stop()

			select {
			case path := <-requests:
				if path != "/v1/traces" {
					t.Fatalf("trace path = %q, want /v1/traces", path)
				}
			default:
				t.Fatal("no HTTP trace request received")
			}
		})
	}
}
