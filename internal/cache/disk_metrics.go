package cache

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
)

type diskReadEvent string

const (
	diskReadEventBreakerTrip       diskReadEvent = "breaker_trip"
	diskReadEventAuthoritativeMiss diskReadEvent = "authoritative_miss"
)

type diskReadOperation string

const (
	diskReadOperationStat              diskReadOperation = "stat"
	diskReadOperationOpen              diskReadOperation = "open"
	diskReadOperationRead              diskReadOperation = "read"
	diskReadOperationClose             diskReadOperation = "close"
	diskReadOperationAuthoritativeStat diskReadOperation = "authoritative_stat"
)

type diskMetricRecorder interface {
	record(context.Context, diskReadEvent, diskReadOperation, BackendType)
}

type diskMetrics struct {
	readEvents metric.Int64Counter
}

// OTel instruments are concurrency-safe process-wide handles; sharing one also
// keeps Tiered construction independent from disk observability wiring.
//
//nolint:gochecknoglobals
var defaultDiskMetrics = newDiskMetrics()

func newDiskMetrics() diskMetricRecorder {
	meter := otel.Meter("cachew.disk")
	return &diskMetrics{
		readEvents: cachewmetrics.NewMetric[metric.Int64Counter](
			meter,
			"cachew.disk.read_events_total",
			"{events}",
			"Disk read breaker trips and authoritative misses, by operation and tier",
		),
	}
}

func (m *diskMetrics) record(
	ctx context.Context,
	event diskReadEvent,
	operation diskReadOperation,
	tier BackendType,
) {
	m.readEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event", string(event)),
		attribute.String("operation", string(operation)),
		attribute.String("tier", string(tier)),
	))
}

func recordDiskReadEvent(
	ctx context.Context,
	metrics diskMetricRecorder,
	event diskReadEvent,
	operation diskReadOperation,
	tier BackendType,
) {
	if metrics != nil {
		metrics.record(ctx, event, operation, tier)
	}
}
