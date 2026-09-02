package cache

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/metrics"
)

func TestObservedBackfillEarlyClose(t *testing.T) {
	previous := otel.GetMeterProvider()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(provider)
	defer func() { otel.SetMeterProvider(previous); assert.NoError(t, provider.Shutdown(context.Background())) }()
	_, ctx := logging.Configure(t.Context(), logging.Config{})
	ctx = metrics.NewArtifactMetrics().WithRequest(ctx, "host", "registry.example", true)
	c, err := NewMemory(ctx, MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	defer c.Close()
	key := NewKey("artifact")
	backfills := newTieredBackfills(ctx)
	lease, ok := backfills.start(ctx, tieredBackfillKey{key: key, etag: "v1"}, "backfill")
	assert.True(t, ok)
	r := newBackfillReadCloser(io.NopCloser(strings.NewReader("artifact")), func(ctx context.Context) (Writer, error) {
		w, err := c.Create(ctx, key, nil, time.Hour)
		return observeWriter(ctx, c, 0, w, err), err
	}, lease)
	p := make([]byte, 2)
	_, err = r.Read(p)
	assert.NoError(t, err)
	assert.NoError(t, r.Close())
	backfills.close() // waits for the asynchronous writer to finish
	_, _, err = c.Open(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
	var data metricdata.ResourceMetrics
	assert.NoError(t, reader.Collect(t.Context(), &data))
	// The fill was canceled; its writer was aborted before commit.
	for name, want := range map[string]string{"cachew.cache.fills": "canceled", "cachew.cache.tier_writes": "aborted"} {
		count := int64(0)
		for _, scope := range data.ScopeMetrics {
			for _, m := range scope.Metrics {
				if m.Name != name {
					continue
				}
				sum := m.Data.(metricdata.Sum[int64])
				for _, point := range sum.DataPoints {
					result, _ := point.Attributes.Value("result")
					assert.Equal(t, want, result.AsString())
					count += point.Value
				}
			}
		}
		assert.Equal(t, int64(1), count)
	}
}

func TestObservedWriterKeepsPendingReads(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{})
	ctx = metrics.NewArtifactMetrics().WithRequest(ctx, "host", "registry.example", true)
	disk, err := NewDisk(ctx, DiskConfig{Root: t.TempDir()})
	assert.NoError(t, err)
	memory, err := NewMemory(ctx, MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	c := MaybeNewTiered(ctx, []Cache{disk, memory}, metadatadb.New(ctx, metadatadb.NewMemoryBackend()))
	defer c.Close()
	w, err := c.Create(ctx, NewKey("artifact"), nil, time.Hour)
	assert.NoError(t, err)
	pending, ok := w.(PendingReader)
	assert.True(t, ok)
	r, err := pending.OpenPending()
	assert.NoError(t, err)
	_, err = io.WriteString(w, "artifact")
	assert.NoError(t, err)
	p := make([]byte, len("artifact"))
	_, err = r.ReadAt(p, 0)
	assert.NoError(t, err)
	assert.Equal(t, "artifact", string(p))
	assert.NoError(t, errors.Join(w.Close(), r.Close()))
}
