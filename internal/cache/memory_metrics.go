package cache

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	cachewmetrics "github.com/block/cachew/internal/metrics"
)

type memoryDeclineReason string

const (
	memoryDeclineDeclaredHardLimit     memoryDeclineReason = "declared_hard_limit"
	memoryDeclineDeclaredInflightLimit memoryDeclineReason = "declared_inflight_limit"
	memoryDeclineWriterReservation     memoryDeclineReason = "writer_reservation"
	memoryDeclineBodyHardLimit         memoryDeclineReason = "body_hard_limit"
	memoryDeclineContentLengthMismatch memoryDeclineReason = "content_length_mismatch"
	memoryDeclineAdmissionLimit        memoryDeclineReason = "admission_limit"
)

type memoryMetricRecorder interface {
	recordDecline(context.Context, memoryDeclineReason)
}

type memoryMetrics struct {
	declines metric.Int64Counter
}

func newMemoryMetrics() memoryMetricRecorder {
	meter := otel.Meter("cachew.memory")
	return &memoryMetrics{
		declines: cachewmetrics.NewMetric[metric.Int64Counter](
			meter,
			"cachew.memory.admission_declines_total",
			"{declines}",
			"Memory-tier writes declined without interrupting authoritative cache tiers, by reason",
		),
	}
}

func (m *memoryMetrics) recordDecline(ctx context.Context, reason memoryDeclineReason) {
	m.declines.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", string(reason))))
}
