package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/logging"
)

func newMemoryTestCache(t *testing.T) *Memory {
	t.Helper()
	return newMemoryTestCacheWithConfig(t, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
}

func newMemoryTestCacheWithConfig(t *testing.T, config MemoryConfig) *Memory {
	t.Helper()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, config)
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	return memory
}

func memoryKeysForShard(t *testing.T, namespace Namespace, shardIndex, count int) []Key {
	t.Helper()
	keys := make([]Key, 0, count)
	for candidate := 0; len(keys) < count; candidate++ {
		key := NewKey(fmt.Sprintf("memory-shard-%d", candidate))
		if memoryShardIndex(namespace, key) == shardIndex {
			keys = append(keys, key)
		}
	}
	return keys
}

func writeMemoryTestEntry(t *testing.T, cache Cache, key Key, data []byte, ttl time.Duration) {
	t.Helper()
	writer, err := cache.Create(t.Context(), key, http.Header{}, ttl)
	assert.NoError(t, err)
	written, err := writer.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), written)
	assert.NoError(t, writer.Close())
}

func newMemoryTestEntry(namespace Namespace, key Key, data []byte) *memoryEntry {
	entry := &memoryEntry{
		namespace: namespace,
		key:       key,
		data:      data,
		expiresAt: time.Now().Add(time.Hour),
		headers:   http.Header{},
	}
	entry.charge = memoryEntryCharge(namespace, data, entry.headers)
	return entry
}

func memoryTestWriter(t testing.TB, writer Writer) *memoryWriter {
	t.Helper()
	memoryWriter, ok := writer.(*memoryWriter)
	assert.True(t, ok)
	return memoryWriter
}

func memoryTestReader(t testing.TB, reader io.ReadCloser) *memoryReader {
	t.Helper()
	memoryReader, ok := reader.(*memoryReader)
	assert.True(t, ok)
	return memoryReader
}

type writeCountingBuffer struct {
	bytes.Buffer
	writes int
}

func (w *writeCountingBuffer) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

type writeOnlyDiscard struct{}

func (writeOnlyDiscard) Write(p []byte) (int, error) { return len(p), nil }

type recordingMemoryMetrics struct {
	mu       sync.Mutex
	declines map[memoryDeclineReason]int
}

func (r *recordingMemoryMetrics) recordDecline(_ context.Context, reason memoryDeclineReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.declines == nil {
		r.declines = make(map[memoryDeclineReason]int)
	}
	r.declines[reason]++
}

func (r *recordingMemoryMetrics) declineCount(reason memoryDeclineReason) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.declines[reason]
}

func memoryWithRecordingMetrics(t *testing.T, config MemoryConfig) (*Memory, *recordingMemoryMetrics) {
	t.Helper()
	memory := newMemoryTestCacheWithConfig(t, config)
	metrics := &recordingMemoryMetrics{}
	memory.state.metrics = metrics
	return memory, metrics
}

func admitMemoryTestEntry(ctx context.Context, t testing.TB, memory *Memory, entry *memoryEntry) {
	t.Helper()
	admitted, err := memory.admit(ctx, entry)
	assert.NoError(t, err)
	assert.True(t, admitted)
}

func assertMemoryAccounting(
	t *testing.T,
	memory *Memory,
	readers []*memoryReader,
	writers []*memoryWriter,
) {
	t.Helper()
	entries := make(map[*memoryEntry]struct{})
	payloadSize := int64(0)
	objectCount := int64(0)
	for index := range memory.state.shards {
		shard := &memory.state.shards[index]
		shard.mu.RLock()
		for _, namespaceEntries := range shard.entries {
			for _, entry := range namespaceEntries {
				if entry.readiness {
					continue
				}
				entries[entry] = struct{}{}
				payloadSize += int64(len(entry.data))
				objectCount++
			}
		}
		shard.mu.RUnlock()
	}
	for _, reader := range readers {
		if !reader.entry.released {
			entries[reader.entry] = struct{}{}
		}
	}

	retainedSize := int64(0)
	for entry := range entries {
		retainedSize += entry.charge
	}
	inflightSize := int64(0)
	hardLimitCharge := retainedSize
	for _, writer := range writers {
		inflightSize += writer.reservedBytes
		if writer.budgeted {
			hardLimitCharge += writer.reservedBytes
		}
	}

	assert.Equal(t, retainedSize, memory.state.retainedCharge.Load())
	assert.Equal(t, inflightSize, memory.state.inflightCharge.Load())
	assert.Equal(t, hardLimitCharge, memory.state.hardLimitCharge.Load())
	assert.Equal(t, payloadSize, memory.state.payloadSize.Load())
	assert.Equal(t, objectCount, memory.state.objectCount.Load())
	if memory.state.limitBytes > 0 {
		assert.True(t, hardLimitCharge <= memory.state.limitBytes)
	}
	if memory.state.inflightLimit > 0 {
		assert.True(t, inflightSize <= memory.state.inflightLimit)
	}
}

type admissionCancellationContext struct {
	context.Context
	firstCheck chan struct{}
	cancelled  atomic.Bool
	once       sync.Once
}

func (c *admissionCancellationContext) Err() error {
	if c.cancelled.Load() {
		return context.Canceled
	}
	c.once.Do(func() { close(c.firstCheck) })
	return nil
}

func TestMemoryShardDoesNotBlockUnrelatedReads(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("sharded")
	keys := memoryKeysForShard(t, namespace, 0, 1)
	otherKeys := memoryKeysForShard(t, namespace, 1, 1)
	cache := memory.Namespace(namespace)
	writeMemoryTestEntry(t, cache, otherKeys[0], []byte("hit"), time.Hour)
	lockedShard := memory.shard(namespace, keys[0])
	lockedShard.mu.Lock()
	defer lockedShard.mu.Unlock()

	result := make(chan error, 1)
	go func() {
		_, err := cache.Stat(t.Context(), otherKeys[0])
		result <- err
	}()

	select {
	case err := <-result:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("cache hit on an unrelated shard blocked")
	}
}

func TestMemoryAdmissionReclaimsCapacityAcrossShards(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("cross-shard")
	fullShardKeys := memoryKeysForShard(t, namespace, 0, 2)
	otherShardKey := memoryKeysForShard(t, namespace, 1, 1)[0]
	cache := memory.Namespace(namespace)
	for _, key := range fullShardKeys {
		writeMemoryTestEntry(t, cache, key, make([]byte, 480*1024), time.Hour)
	}

	writeMemoryTestEntry(t, cache, otherShardKey, make([]byte, 128*1024), time.Hour)

	reader, _, err := cache.Open(t.Context(), otherShardKey)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
}

func TestMemoryEvictionRetainsRecentlyReadEntry(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("clock")
	keys := memoryKeysForShard(t, namespace, 0, 3)
	cache := memory.Namespace(namespace)
	entryData := make([]byte, 400*1024)
	writeMemoryTestEntry(t, cache, keys[0], entryData, time.Hour)
	writeMemoryTestEntry(t, cache, keys[1], entryData, time.Hour)
	reader, _, err := cache.Open(t.Context(), keys[0])
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())

	writeMemoryTestEntry(t, cache, keys[2], entryData, time.Hour)

	reader, _, err = cache.Open(t.Context(), keys[0])
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	_, _, err = cache.Open(t.Context(), keys[1])
	assert.IsError(t, err, os.ErrNotExist)
}

func TestMemoryEvictionPrefersColdEntryFromAnotherShard(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("cross-shard-clock")
	hotKey := memoryKeysForShard(t, namespace, 0, 1)[0]
	coldKey := memoryKeysForShard(t, namespace, 1, 1)[0]
	newKey := memoryKeysForShard(t, namespace, 2, 1)[0]
	cache := memory.Namespace(namespace)
	entryData := make([]byte, 400*1024)
	writeMemoryTestEntry(t, cache, hotKey, entryData, time.Hour)
	writeMemoryTestEntry(t, cache, coldKey, entryData, time.Hour)
	reader, _, err := cache.Open(t.Context(), hotKey)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	memory.state.evictionCursor.Store(0)

	writeMemoryTestEntry(t, cache, newKey, entryData, time.Hour)

	for _, key := range []Key{hotKey, newKey} {
		reader, _, err = cache.Open(t.Context(), key)
		assert.NoError(t, err)
		assert.NoError(t, reader.Close())
	}
	_, _, err = cache.Open(t.Context(), coldKey)
	assert.IsError(t, err, os.ErrNotExist)
}

func TestMemoryZeroLengthEntriesConsumeCapacity(t *testing.T) {
	memory := newMemoryTestCache(t)
	cache := memory.Namespace("metadata")
	for index := range 400 {
		writeMemoryTestEntry(t, cache, NewKey(fmt.Sprintf("zero-%d", index)), nil, time.Hour)
	}

	stats, err := cache.Stats(t.Context())
	assert.NoError(t, err)
	assert.True(t, stats.Objects < 400)
	assert.Equal(t, int64(0), stats.Size)
	assert.True(t, memory.state.retainedCharge.Load() > 0)
	assert.True(t, memory.state.retainedCharge.Load() <= stats.Capacity)
}

func TestMemoryInflightBuffersAreBounded(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 4, InflightLimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	writers := make([]Writer, 0, 16)
	for index := range 16 {
		writer, err := memory.Create(t.Context(), NewKey(fmt.Sprintf("inflight-%d", index)), nil, time.Hour)
		assert.NoError(t, err)
		_, err = writer.Write(make([]byte, 256*1024))
		assert.NoError(t, err)
		writers = append(writers, writer)
	}

	activeWriters := 0
	reservedBytes := int64(0)
	for _, writer := range writers {
		memoryWriter := memoryTestWriter(t, writer)
		if memoryWriter.discarded {
			continue
		}
		activeWriters++
		reservedBytes += memoryWriter.reservedBytes
		assert.Equal(t, memoryWriter.baseCharge+int64(cap(memoryWriter.data)), memoryWriter.reservedBytes)
	}
	assert.True(t, activeWriters > 0)
	assert.True(t, activeWriters < len(writers))
	assert.Equal(t, reservedBytes, memory.state.inflightCharge.Load())
	assert.True(t, memory.state.inflightCharge.Load() <= memory.state.inflightLimit)
	for _, writer := range writers {
		assert.NoError(t, writer.Close())
	}
	assert.Equal(t, int64(0), memory.state.inflightCharge.Load())
	stats, err := memory.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(activeWriters), stats.Objects)
}

func TestMemoryDefaultDoesNotLimitInflightBuffers(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	writers := make([]Writer, 0, 2)
	for index := range 2 {
		writer, err := memory.Create(t.Context(), NewKey(fmt.Sprintf("unbounded-inflight-%d", index)), nil, time.Hour)
		assert.NoError(t, err)
		_, err = writer.Write(make([]byte, 600*1024))
		assert.NoError(t, err)
		memoryWriter := memoryTestWriter(t, writer)
		assert.False(t, memoryWriter.discarded)
		writers = append(writers, writer)
	}
	assert.Equal(t, int64(0), memory.state.inflightLimit)
	assert.True(t, memory.state.inflightCharge.Load() > memory.state.limitBytes)
	for _, writer := range writers {
		assert.NoError(t, writer.Close())
	}
	assert.Equal(t, int64(0), memory.state.inflightCharge.Load())
	assert.True(t, memory.state.retainedCharge.Load() <= memory.state.limitBytes)
}

func TestMemoryConfiguredInflightSharesHardBudget(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 4, InflightLimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	oldKey := NewKey("retained-before-inflight")
	admitted, err := memory.tryAdmission(
		ctx,
		newMemoryTestEntry("", oldKey, make([]byte, 3500*1024)),
		memory.state.limitBytes,
		memoryAdmissionNeedsAllocation,
	)
	assert.NoError(t, err)
	assert.True(t, admitted)

	newKey := NewKey("configured-inflight")
	writer, err := memory.Create(ctx, newKey, nil, time.Hour)
	assert.NoError(t, err)
	_, err = writer.Write(make([]byte, 768*1024))
	assert.NoError(t, err)
	memoryWriter := memoryTestWriter(t, writer)
	assert.False(t, memoryWriter.discarded)
	assert.True(t, memory.state.hardLimitCharge.Load() <= memory.state.limitBytes)
	assert.True(t, memory.state.inflightCharge.Load() <= memory.state.inflightLimit)
	assert.NoError(t, writer.Close())

	reader, _, err := memory.Open(ctx, newKey)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, int64(0), memory.state.inflightCharge.Load())
	assert.True(t, memory.state.hardLimitCharge.Load() <= memory.state.limitBytes)
	assert.True(t, memory.state.retainedCharge.Load() <= memory.state.limitBytes)
}

func TestMemorySlowAdmissionDoesNotBlockUnrelatedHits(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("concurrent-hits")
	blockedKey := memoryKeysForShard(t, namespace, 0, 1)[0]
	hitKey := memoryKeysForShard(t, namespace, 1, 1)[0]
	newKey := memoryKeysForShard(t, namespace, 2, 1)[0]
	deleteKey := memoryKeysForShard(t, namespace, 3, 1)[0]
	cache := memory.Namespace(namespace)
	entryData := make([]byte, 400*1024)
	writeMemoryTestEntry(t, cache, blockedKey, entryData, time.Hour)
	writeMemoryTestEntry(t, cache, hitKey, entryData, time.Hour)
	writeMemoryTestEntry(t, cache, deleteKey, make([]byte, 64*1024), time.Hour)
	writer, err := cache.Create(t.Context(), newKey, nil, time.Hour)
	assert.NoError(t, err)
	_, err = writer.Write(entryData)
	assert.NoError(t, err)
	memory.state.evictionCursor.Store(0)
	blockedShard := memory.shard(namespace, blockedKey)
	blockedShard.mu.Lock()

	closed := make(chan error, 1)
	go func() {
		closed <- writer.Close()
	}()
	deadline := time.Now().Add(time.Second)
	for memory.state.evictionCursor.Load() == 0 {
		if time.Now().After(deadline) {
			blockedShard.mu.Unlock()
			t.Fatal("admission did not reach the capacity path")
		}
		time.Sleep(time.Millisecond)
	}

	hitReader, _, err := cache.Open(t.Context(), hitKey)
	assert.NoError(t, err)
	assert.NoError(t, hitReader.Close())
	deleted := make(chan error, 1)
	go func() { deleted <- cache.Delete(t.Context(), deleteKey) }()
	select {
	case err := <-deleted:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		blockedShard.mu.Unlock()
		t.Fatal("delete on an unrelated shard blocked")
	}
	blockedShard.mu.Unlock()
	select {
	case err := <-closed:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("admission did not finish after the shard was released")
	}
}

func TestMemoryAdmissionAtCapacityEvictsExistingEntry(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("eviction")
	keys := memoryKeysForShard(t, namespace, 0, 3)
	cache := memory.Namespace(namespace)
	writeMemoryTestEntry(t, cache, keys[0], make([]byte, 512*1024), 3*time.Hour)
	writeMemoryTestEntry(t, cache, keys[1], make([]byte, 512*1024), time.Minute)
	writeMemoryTestEntry(t, cache, keys[2], make([]byte, 128*1024), 2*time.Hour)

	_, err := cache.Stat(t.Context(), keys[2])
	assert.NoError(t, err)
	stats, err := cache.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(2), stats.Objects)
	assert.True(t, stats.Size >= int64(640*1024))
	assert.True(t, stats.Size <= stats.Capacity)
}

func TestMemoryReplacementKeepsUnrelatedEntries(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("replacement")
	keys := memoryKeysForShard(t, namespace, 0, 2)
	cache := memory.Namespace(namespace)
	writeMemoryTestEntry(t, cache, keys[0], make([]byte, 40*1024), time.Minute)
	writeMemoryTestEntry(t, cache, keys[1], make([]byte, 20*1024), 2*time.Hour)
	replacement := make([]byte, 40*1024)
	replacement[0] = 1
	writeMemoryTestEntry(t, cache, keys[0], replacement, 3*time.Hour)

	reader, _, err := cache.Open(t.Context(), keys[0])
	assert.NoError(t, err)
	data, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, byte(1), data[0])
	_, err = cache.Stat(t.Context(), keys[1])
	assert.NoError(t, err)
	stats, err := cache.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(2), stats.Objects)
	assert.True(t, stats.Size >= int64(60*1024))
	assert.True(t, stats.Size <= stats.Capacity)
}

func TestMemoryReplacementKeepsReaderChargedUntilClose(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 2, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	key := NewKey("reader-replacement")
	oldData := make([]byte, 600*1024)
	writeMemoryTestEntry(t, memory, key, oldData, time.Hour)
	oldReader, _, err := memory.Open(t.Context(), key)
	assert.NoError(t, err)
	oneGeneration := memory.state.retainedCharge.Load()
	newData := make([]byte, len(oldData))
	newData[0] = 1

	writeMemoryTestEntry(t, memory, key, newData, time.Hour)
	assert.True(t, memory.state.retainedCharge.Load() > oneGeneration)
	storedOld, err := io.ReadAll(oldReader)
	assert.NoError(t, err)
	assert.Equal(t, byte(0), storedOld[0])
	assert.NoError(t, oldReader.Close())
	assert.Equal(t, oneGeneration, memory.state.retainedCharge.Load())
	assert.Equal(t, oneGeneration, memory.state.hardLimitCharge.Load())

	newReader, _, err := memory.Open(t.Context(), key)
	assert.NoError(t, err)
	storedNew, err := io.ReadAll(newReader)
	assert.NoError(t, err)
	assert.NoError(t, newReader.Close())
	assert.Equal(t, byte(1), storedNew[0])
}

func TestMemoryConfiguredBudgetAccountingAcrossTransitions(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 4, InflightLimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	key := NewKey("accounting-transitions")

	writer, err := memory.Create(ctx, key, nil, time.Hour)
	assert.NoError(t, err)
	bufferedWriter := memoryTestWriter(t, writer)
	_, err = writer.Write(make([]byte, 256*1024))
	assert.NoError(t, err)
	assertMemoryAccounting(t, memory, nil, []*memoryWriter{bufferedWriter})
	assert.NoError(t, writer.Close())
	assertMemoryAccounting(t, memory, nil, []*memoryWriter{bufferedWriter})

	reader, _, err := memory.Open(ctx, key)
	assert.NoError(t, err)
	pinnedReader := memoryTestReader(t, reader)
	replacement, err := memory.Create(ctx, key, nil, time.Hour)
	assert.NoError(t, err)
	replacementWriter := memoryTestWriter(t, replacement)
	_, err = replacement.Write(make([]byte, 128*1024))
	assert.NoError(t, err)
	assertMemoryAccounting(t, memory, []*memoryReader{pinnedReader}, []*memoryWriter{replacementWriter})
	assert.NoError(t, replacement.Close())
	assertMemoryAccounting(t, memory, []*memoryReader{pinnedReader}, []*memoryWriter{replacementWriter})

	oldData, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, 256*1024, len(oldData))
	assert.NoError(t, reader.Close())
	assertMemoryAccounting(t, memory, []*memoryReader{pinnedReader}, nil)

	aborted, err := memory.Create(ctx, NewKey("aborted-accounting"), nil, time.Hour)
	assert.NoError(t, err)
	abortedWriter := memoryTestWriter(t, aborted)
	_, err = aborted.Write(make([]byte, 64*1024))
	assert.NoError(t, err)
	assertMemoryAccounting(t, memory, nil, []*memoryWriter{abortedWriter})
	assert.IsError(t, aborted.Abort(errors.New("abort accounting write")), context.Canceled)
	assertMemoryAccounting(t, memory, nil, []*memoryWriter{abortedWriter})

	assert.NoError(t, memory.Delete(ctx, key))
	assertMemoryAccounting(t, memory, nil, nil)

	shutdownKey := NewKey("shutdown-accounting")
	writeMemoryTestEntry(t, memory, shutdownKey, make([]byte, 32*1024), time.Hour)
	shutdownReader, _, err := memory.Open(ctx, shutdownKey)
	assert.NoError(t, err)
	pinnedShutdownReader := memoryTestReader(t, shutdownReader)
	assert.NoError(t, memory.Close())
	assertMemoryAccounting(t, memory, []*memoryReader{pinnedShutdownReader}, nil)
	assert.NoError(t, shutdownReader.Close())
	assertMemoryAccounting(t, memory, []*memoryReader{pinnedShutdownReader}, nil)
}

func TestMemoryStatsUsePayloadBytesWithoutTakingShardLocks(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("stats")
	key := memoryKeysForShard(t, namespace, 0, 1)[0]
	cache := memory.Namespace(namespace)
	payload := []byte("payload")
	writeMemoryTestEntry(t, cache, key, payload, time.Hour)
	shard := memory.shard(namespace, key)
	shard.mu.Lock()
	type statsResult struct {
		stats Stats
		err   error
	}
	result := make(chan statsResult, 1)
	go func() {
		stats, err := cache.Stats(t.Context())
		result <- statsResult{stats: stats, err: err}
	}()
	var response statsResult
	select {
	case response = <-result:
	case <-time.After(time.Second):
		shard.mu.Unlock()
		t.Fatal("stats blocked on a shard lock")
	}
	shard.mu.Unlock()
	stats, err := response.stats, response.err
	assert.NoError(t, err)
	assert.Equal(t, int64(1), stats.Objects)
	assert.Equal(t, int64(len(payload)), stats.Size)
	assert.True(t, memory.state.retainedCharge.Load() > stats.Size)
}

func TestMemoryUnlimitedAccountingReturnsToZero(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 0, MaxTTL: time.Hour})
	assert.NoError(t, err)
	key := NewKey("unlimited")
	writeMemoryTestEntry(t, memory, key, []byte("payload"), time.Hour)
	assert.True(t, memory.state.retainedCharge.Load() > 0)

	assert.NoError(t, memory.Delete(t.Context(), key))
	assert.Equal(t, int64(0), memory.state.retainedCharge.Load())
	assert.Equal(t, int64(0), memory.state.hardLimitCharge.Load())
	assert.NoError(t, memory.Close())
}

func TestMemoryOversizedWriteDoesNotReplaceExistingEntry(t *testing.T) {
	memory := newMemoryTestCache(t)
	namespace := Namespace("oversized")
	key := memoryKeysForShard(t, namespace, 0, 1)[0]
	cache := memory.Namespace(namespace)
	writeMemoryTestEntry(t, cache, key, []byte("old"), time.Hour)

	limitBytes := int64(memory.config.LimitMB) * 1024 * 1024
	writeMemoryTestEntry(t, cache, key, make([]byte, limitBytes+1), time.Hour)

	reader, _, err := cache.Open(t.Context(), key)
	assert.NoError(t, err)
	data, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, "old", string(data))
}

func TestMemoryKnownOversizedWriteIsNotAdmitted(t *testing.T) {
	memory := newMemoryTestCache(t)
	key := NewKey("known-oversized")
	limitBytes := int64(memory.config.LimitMB) * 1024 * 1024
	w, err := memory.Create(t.Context(), key, http.Header{"Content-Length": {strconv.FormatInt(limitBytes+1, 10)}}, time.Hour)
	assert.NoError(t, err)
	_, err = w.Write([]byte("partial prefix"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())
	_, _, err = memory.Open(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
}

func TestMemoryPartialWriteIsNotAdmitted(t *testing.T) {
	memory := newMemoryTestCache(t)
	key := NewKey("partial")
	w, err := memory.Create(t.Context(), key, http.Header{"Content-Length": {"10"}}, time.Hour)
	assert.NoError(t, err)
	_, err = w.Write([]byte("abc"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())
	_, _, err = memory.Open(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
}

func TestMemoryDeclaredLengthDoesNotAllocateBeforeWrite(t *testing.T) {
	memory := newMemoryTestCacheWithConfig(t, MemoryConfig{MaxTTL: time.Hour})
	declaredLength := 16 * 1024 * 1024
	writer, err := memory.Create(t.Context(), NewKey("lazy-declared-length"), http.Header{
		"Content-Length": {strconv.Itoa(declaredLength)},
	}, time.Hour)
	assert.NoError(t, err)
	memoryWriter := memoryTestWriter(t, writer)
	assert.Equal(t, 0, cap(memoryWriter.data))
	assert.Equal(t, memoryWriter.baseCharge, memoryWriter.reservedBytes)
	assert.NoError(t, writer.Close())
	assert.Equal(t, int64(0), memory.state.inflightCharge.Load())
}

func TestMemoryDeclaredLengthCapsFinalBufferCapacity(t *testing.T) {
	memory := newMemoryTestCacheWithConfig(t, MemoryConfig{LimitMB: 4, InflightLimitMB: 2, MaxTTL: time.Hour})
	declaredLength := 1024*1024 + 1
	payload := bytes.Repeat([]byte{0x5a}, declaredLength)
	writer, err := memory.Create(t.Context(), NewKey("exact-declared-capacity"), http.Header{
		"Content-Length": {strconv.Itoa(declaredLength)},
	}, time.Hour)
	assert.NoError(t, err)
	written, err := writer.Write(payload[:1024*1024])
	assert.NoError(t, err)
	assert.Equal(t, 1024*1024, written)
	written, err = writer.Write(payload[1024*1024:])
	assert.NoError(t, err)
	assert.Equal(t, 1, written)
	memoryWriter := memoryTestWriter(t, writer)
	assert.Equal(t, declaredLength, cap(memoryWriter.data))
	assert.NoError(t, writer.Close())
}

func TestMemoryReaderPreservesWriterToFastPath(t *testing.T) {
	memory := newMemoryTestCache(t)
	key := NewKey("writer-to-fast-path")
	payload := bytes.Repeat([]byte{0x6b}, 96*1024)
	writeMemoryTestEntry(t, memory, key, payload, time.Hour)
	reader, _, err := memory.Open(t.Context(), key)
	assert.NoError(t, err)
	prefix := make([]byte, 1024)
	read, err := reader.Read(prefix)
	assert.NoError(t, err)
	assert.Equal(t, len(prefix), read)
	writerTo, ok := reader.(io.WriterTo)
	assert.True(t, ok)
	destination := &writeCountingBuffer{}
	written, err := writerTo.WriteTo(destination)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(payload)-len(prefix)), written)
	assert.Equal(t, 1, destination.writes)
	assert.Equal(t, payload[len(prefix):], destination.Bytes())
	assert.NoError(t, reader.Close())
}

func TestMemoryUnknownLengthAdmissionDoesNotDependOnWriteChunks(t *testing.T) {
	memory := newMemoryTestCacheWithConfig(t, MemoryConfig{LimitMB: 2, InflightLimitMB: 1, MaxTTL: time.Hour})
	key := NewKey("chunked-unknown-length")
	writer, err := memory.Create(t.Context(), key, http.Header{}, time.Hour)
	assert.NoError(t, err)
	payload := bytes.Repeat([]byte{0x7a}, 640*1024)
	for offset := 0; offset < len(payload); offset += 64 * 1024 {
		written, err := writer.Write(payload[offset : offset+64*1024])
		assert.NoError(t, err)
		assert.Equal(t, 64*1024, written)
	}
	assert.NoError(t, writer.Close())

	reader, _, err := memory.Open(t.Context(), key)
	assert.NoError(t, err)
	stored, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, payload, stored)
}

func TestMemorySmallUnknownLengthUsesMinimumCapacity(t *testing.T) {
	memory := newMemoryTestCache(t)
	writer, err := memory.Create(t.Context(), NewKey("small-unknown-length"), nil, time.Hour)
	assert.NoError(t, err)
	written, err := writer.Write([]byte{1})
	assert.NoError(t, err)
	assert.Equal(t, 1, written)
	assert.Equal(t, memoryWriterInitialCapacity, cap(memoryTestWriter(t, writer).data))
	assert.NoError(t, writer.Close())
}

func TestMemoryRecordsAdmissionDeclineReasons(t *testing.T) {
	t.Run("declared hard limit", func(t *testing.T) {
		memory, metrics := memoryWithRecordingMetrics(t, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
		writer, err := memory.Create(t.Context(), NewKey("declared-hard-limit"), http.Header{
			"Content-Length": {strconv.Itoa(2 * 1024 * 1024)},
		}, time.Hour)
		assert.NoError(t, err)
		assert.NoError(t, writer.Close())
		assert.Equal(t, 1, metrics.declineCount(memoryDeclineDeclaredHardLimit))
	})

	t.Run("declared inflight limit", func(t *testing.T) {
		memory, metrics := memoryWithRecordingMetrics(t, MemoryConfig{LimitMB: 4, InflightLimitMB: 1, MaxTTL: time.Hour})
		writer, err := memory.Create(t.Context(), NewKey("declared-inflight-limit"), http.Header{
			"Content-Length": {strconv.Itoa(1024 * 1024)},
		}, time.Hour)
		assert.NoError(t, err)
		assert.NoError(t, writer.Close())
		assert.Equal(t, 1, metrics.declineCount(memoryDeclineDeclaredInflightLimit))
	})

	t.Run("writer reservation", func(t *testing.T) {
		memory, metrics := memoryWithRecordingMetrics(t, MemoryConfig{LimitMB: 4, InflightLimitMB: 1, MaxTTL: time.Hour})
		memory.state.inflightCharge.Store(memory.state.inflightLimit)
		writer, err := memory.Create(t.Context(), NewKey("writer-reservation"), nil, time.Hour)
		assert.NoError(t, err)
		assert.NoError(t, writer.Close())
		memory.state.inflightCharge.Store(0)
		assert.Equal(t, 1, metrics.declineCount(memoryDeclineWriterReservation))
	})

	t.Run("body hard limit", func(t *testing.T) {
		memory, metrics := memoryWithRecordingMetrics(t, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
		writer, err := memory.Create(t.Context(), NewKey("body-hard-limit"), nil, time.Hour)
		assert.NoError(t, err)
		written, err := writer.Write(make([]byte, 2*1024*1024))
		assert.NoError(t, err)
		assert.Equal(t, 2*1024*1024, written)
		assert.NoError(t, writer.Close())
		assert.Equal(t, 1, metrics.declineCount(memoryDeclineBodyHardLimit))
	})

	t.Run("content length mismatch", func(t *testing.T) {
		memory, metrics := memoryWithRecordingMetrics(t, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
		writer, err := memory.Create(t.Context(), NewKey("content-length-mismatch"), http.Header{
			"Content-Length": {"1"},
		}, time.Hour)
		assert.NoError(t, err)
		assert.NoError(t, writer.Close())
		assert.Equal(t, 1, metrics.declineCount(memoryDeclineContentLengthMismatch))
	})

	t.Run("admission limit", func(t *testing.T) {
		memory, metrics := memoryWithRecordingMetrics(t, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
		keys := make([]Key, 0, memory.state.limitBytes/memoryEntryMinimumCharge)
		for index := range cap(keys) {
			key := NewKey(fmt.Sprintf("admission-limit-%d", index))
			keys = append(keys, key)
			writeMemoryTestEntry(t, memory, key, nil, time.Hour)
		}
		for _, key := range keys {
			_, err := memory.Stat(t.Context(), key)
			assert.NoError(t, err)
		}
		writer, err := memory.Create(t.Context(), NewKey("declined-admission"), nil, time.Hour)
		assert.NoError(t, err)
		assert.NoError(t, writer.Close())
		assert.Equal(t, 1, metrics.declineCount(memoryDeclineAdmissionLimit))
	})
}

func TestMemoryRejectsInvalidLimits(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	type invalidLimitTest struct {
		name   string
		config MemoryConfig
	}
	tests := []invalidLimitTest{
		{name: "negative retained limit", config: MemoryConfig{LimitMB: -1}},
		{name: "negative inflight limit", config: MemoryConfig{InflightLimitMB: -1}},
		{name: "inflight limit equals retained limit", config: MemoryConfig{LimitMB: 8, InflightLimitMB: 8}},
		{name: "inflight limit exceeds retained limit", config: MemoryConfig{LimitMB: 8, InflightLimitMB: 9}},
	}
	if strconv.IntSize == 64 {
		overflowMB := int(math.MaxInt64/(1024*1024) + 1)
		tests = append(tests,
			invalidLimitTest{name: "overflowing retained limit", config: MemoryConfig{LimitMB: overflowMB}},
			invalidLimitTest{name: "overflowing inflight limit", config: MemoryConfig{InflightLimitMB: overflowMB}},
		)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			memory, err := NewMemory(ctx, test.config)
			if memory != nil {
				assert.NoError(t, memory.Close())
			}
			assert.Error(t, err)
		})
	}
}

func TestMemoryUnlimitedRetentionSurvivesInflightPressure(t *testing.T) {
	memory := newMemoryTestCacheWithConfig(t, MemoryConfig{InflightLimitMB: 1, MaxTTL: time.Hour})
	for _, key := range []Key{NewKey("unlimited-retention-first"), NewKey("unlimited-retention-second")} {
		writer, err := memory.Create(t.Context(), key, nil, time.Hour)
		assert.NoError(t, err)
		written, err := writer.Write(make([]byte, 768*1024))
		assert.NoError(t, err)
		assert.Equal(t, 768*1024, written)
		assert.NoError(t, writer.Close())
	}
	before, err := memory.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(2), before.Objects)
	assert.True(t, memory.state.retainedCharge.Load() > memory.state.inflightLimit)

	pressure, err := memory.Create(t.Context(), NewKey("unlimited-inflight-pressure"), nil, time.Hour)
	assert.NoError(t, err)
	written, err := pressure.Write(make([]byte, 1024*1024-memoryWriterMinimumCharge))
	assert.NoError(t, err)
	assert.Equal(t, 1024*1024-memoryWriterMinimumCharge, written)
	assert.Equal(t, memory.state.inflightLimit, memory.state.inflightCharge.Load())

	declined, err := memory.Create(t.Context(), NewKey("unlimited-inflight-declined"), nil, time.Hour)
	assert.NoError(t, err)
	assert.NoError(t, declined.Close())
	after, err := memory.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, before, after)
	assert.IsError(t, pressure.Abort(errors.New("release inflight pressure")), context.Canceled)
}

func TestMemoryCancelledAdmissionDoesNotEvictEntries(t *testing.T) {
	memory := newMemoryTestCache(t)
	const namespace Namespace = "cancelled-admission"
	oldKeys := []Key{
		memoryKeysForShard(t, namespace, 0, 1)[0],
		memoryKeysForShard(t, namespace, 1, 1)[0],
	}
	newKey := memoryKeysForShard(t, namespace, 2, 1)[0]
	cache := memory.Namespace(namespace)
	for _, key := range oldKeys {
		writeMemoryTestEntry(t, cache, key, make([]byte, 480*1024), time.Hour)
	}

	ctx, cancel := context.WithCancel(t.Context())
	blockedShard := memory.shard(namespace, oldKeys[0])
	memory.state.evictionCursor.Store(0)
	blockedShard.mu.Lock()
	shardLocked := true
	t.Cleanup(func() {
		if shardLocked {
			blockedShard.mu.Unlock()
		}
	})
	type admissionResult struct {
		admitted bool
		err      error
	}
	result := make(chan admissionResult, 1)
	go func() {
		admitted, err := memory.admit(ctx, newMemoryTestEntry(namespace, newKey, make([]byte, 128*1024)))
		result <- admissionResult{admitted: admitted, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for memory.state.evictionCursor.Load() == 0 {
		if time.Now().After(deadline) {
			blockedShard.mu.Unlock()
			shardLocked = false
			t.Fatal("admission did not reach eviction planning")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	blockedShard.mu.Unlock()
	shardLocked = false

	var response admissionResult
	select {
	case response = <-result:
	case <-time.After(time.Second):
		t.Fatal("cancelled admission did not return")
	}
	assert.False(t, response.admitted)
	assert.IsError(t, response.err, context.Canceled)
	for _, key := range oldKeys {
		reader, _, err := cache.Open(t.Context(), key)
		assert.NoError(t, err)
		assert.NoError(t, reader.Close())
	}
	_, _, err := cache.Open(t.Context(), newKey)
	assert.IsError(t, err, os.ErrNotExist)
}

func TestMemoryCancellationWhileWaitingForAdmissionIsNotAdmitted(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 2, InflightLimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	key := NewKey("cancel-race")
	w, err := memory.Create(t.Context(), key, nil, time.Hour)
	assert.NoError(t, err)
	_, err = w.Write([]byte("cancelled"))
	assert.NoError(t, err)
	controlledContext := &admissionCancellationContext{Context: t.Context(), firstCheck: make(chan struct{})}
	memoryWriter := memoryTestWriter(t, w)
	memoryWriter.ctx = controlledContext

	shard := memory.shard("", key)
	shard.mu.Lock()
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	<-controlledContext.firstCheck
	controlledContext.cancelled.Store(true)
	shard.mu.Unlock()

	assert.IsError(t, <-closed, context.Canceled)
	_, _, err = memory.Open(t.Context(), key)
	assert.IsError(t, err, os.ErrNotExist)
	assert.Equal(t, int64(0), memory.state.inflightCharge.Load())
	assert.Equal(t, int64(0), memory.state.hardLimitCharge.Load())
}

func TestMemoryConcurrentAdmissionKeepsAccountingBounded(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 8, InflightLimitMB: 2, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	const writes = 64
	keys := make([]Key, writes)
	writeErrors := make(chan error, writes)
	var wg sync.WaitGroup
	for index := range writes {
		keys[index] = NewKey(fmt.Sprintf("concurrent-%d", index))
		wg.Go(func() {
			writer, err := memory.Create(t.Context(), keys[index], http.Header{}, time.Hour)
			if err == nil {
				_, err = writer.Write(make([]byte, 32*1024))
			}
			if err == nil {
				err = writer.Close()
			}
			writeErrors <- err
		})
	}
	wg.Wait()
	close(writeErrors)
	for err := range writeErrors {
		assert.NoError(t, err)
	}

	stats, err := memory.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(0), memory.state.inflightCharge.Load())
	assert.True(t, memory.state.hardLimitCharge.Load() <= memory.state.limitBytes)
	actualObjects := int64(0)
	actualSize := int64(0)
	for _, key := range keys {
		reader, _, err := memory.Open(t.Context(), key)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		assert.NoError(t, err)
		data, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.NoError(t, reader.Close())
		actualObjects++
		actualSize += int64(len(data))
	}
	assert.Equal(t, actualObjects, stats.Objects)
	assert.Equal(t, actualSize, stats.Size)
	assert.True(t, actualObjects > 1)
}

func TestMemoryConcurrentReplacementDoesNotExposeCapacity(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 0, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	const namespace Namespace = "replacement-accounting"
	payload := make([]byte, 64*1024)
	keys := make([]Key, memoryShardCount)
	for shardIndex := range memoryShardCount {
		keys[shardIndex] = memoryKeysForShard(t, namespace, shardIndex, 1)[0]
		admitMemoryTestEntry(t.Context(), t, memory, newMemoryTestEntry(namespace, keys[shardIndex], payload))
	}
	memory.state.limitBytes = memory.state.retainedCharge.Load()
	retainedCeiling := memory.state.limitBytes + memoryEntryMinimumCharge
	memory.state.limitBytes = retainedCeiling
	memory.state.retainedTarget = retainedCeiling - memoryEntryMinimumCharge

	workContext, cancelWork := context.WithCancel(t.Context())
	start := make(chan struct{})
	var stopped atomic.Bool
	var observedMaximum atomic.Int64
	var replacements atomic.Int64
	var admissions atomic.Int64
	var wait sync.WaitGroup
	for _, key := range keys {
		wait.Go(func() {
			<-start
			for !stopped.Load() {
				admitted, err := memory.admit(workContext, newMemoryTestEntry(namespace, key, payload))
				if err != nil {
					return
				}
				if admitted {
					replacements.Add(1)
				}
			}
		})
	}
	for worker := range 8 {
		wait.Go(func() {
			<-start
			for index := 0; !stopped.Load(); index++ {
				key := NewKey(fmt.Sprintf("replacement-admission-%d-%d", worker, index))
				admitted, err := memory.admit(workContext, newMemoryTestEntry(namespace, key, nil))
				if err != nil {
					return
				}
				if admitted {
					admissions.Add(1)
				}
			}
		})
	}

	close(start)
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		size := memory.state.hardLimitCharge.Load()
		for maximum := observedMaximum.Load(); size > maximum; maximum = observedMaximum.Load() {
			if observedMaximum.CompareAndSwap(maximum, size) {
				break
			}
		}
		if size > retainedCeiling {
			break
		}
	}
	stopped.Store(true)
	cancelWork()
	wait.Wait()
	assert.True(t, replacements.Load() > 0)
	assert.True(t, admissions.Load() > 0)
	assert.True(t, observedMaximum.Load() <= retainedCeiling,
		"retained charge exceeded ceiling: got %d, ceiling %d", observedMaximum.Load(), retainedCeiling)
}

func TestMemoryReadinessExercisesEveryShard(t *testing.T) {
	memory := newMemoryTestCache(t)
	deadline := time.Now().Add(2 * time.Second)
	for !memory.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.True(t, memory.Ready())

	seen := make(map[int]bool, memoryShardCount)
	for index, key := range memory.state.readiness.keys {
		shardIndex := memoryShardIndex(memoryReadinessNamespace, key)
		assert.Equal(t, index, shardIndex)
		seen[shardIndex] = true
		reader, _, err := memory.state.readiness.cache.Open(t.Context(), key)
		assert.NoError(t, err)
		body, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.NoError(t, reader.Close())
		assert.Equal(t, memoryReadinessPayload(index), body)
	}
	assert.Equal(t, memoryShardCount, len(seen))
	stats, err := memory.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(0), stats.Objects)
	assert.Equal(t, int64(0), stats.Size)
	namespaces, err := memory.ListNamespaces(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, []string{}, namespaces)
}

func TestMemoryReadinessSentinelCannotBeReplaced(t *testing.T) {
	memory := newMemoryTestCache(t)
	const shardIndex = 0
	key := memory.state.readiness.keys[shardIndex]
	ordinaryKey := memoryKeysForShard(t, "", shardIndex, 1)[0]
	writeMemoryTestEntry(t, memory, ordinaryKey, []byte("ordinary"), time.Hour)

	writer, err := memory.state.readiness.cache.Create(t.Context(), key, nil, time.Hour)
	assert.NoError(t, err)
	_, err = writer.Write([]byte("replacement"))
	assert.NoError(t, err)
	assert.True(t, errors.Is(writer.Close(), os.ErrPermission))

	reader, _, err := memory.state.readiness.cache.Open(t.Context(), key)
	assert.NoError(t, err)
	body, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, memoryReadinessPayload(shardIndex), body)
	reader, _, err = memory.Open(t.Context(), ordinaryKey)
	assert.NoError(t, err)
	body, err = io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, []byte("ordinary"), body)
	stats, err := memory.Stats(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, int64(1), stats.Objects)
	assert.Equal(t, int64(len("ordinary")), stats.Size)
}

func TestMemoryReadinessFailsWithoutBlockingWhenShardStalls(t *testing.T) {
	memory := newMemoryTestCache(t)
	deadline := time.Now().Add(2 * time.Second)
	for !memory.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.True(t, memory.Ready())

	const shardIndex = 3
	shard := &memory.state.shards[shardIndex]
	shard.mu.Lock()
	probeDone := make(chan struct{})
	go func() {
		memory.state.readiness.probe(shardIndex)
		close(probeDone)
	}()
	select {
	case <-probeDone:
		shard.mu.Unlock()
		t.Fatal("readiness probe did not traverse the blocked shard")
	case <-time.After(50 * time.Millisecond):
	}
	elapsed := time.Since(memory.state.readiness.startedAt)
	memory.state.readiness.lastSuccess[shardIndex].Store(
		elapsed.Nanoseconds() - int64(2*memoryReadinessStaleAfter) + 1,
	)
	assert.False(t, memory.Ready())
	shard.mu.Unlock()

	select {
	case <-probeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("readiness probe did not recover after the shard was released")
	}
	assert.True(t, memory.Ready())
}

func TestMemoryUncommittedPlanDoesNotHideEntries(t *testing.T) {
	memory := newMemoryTestCache(t)
	const namespace Namespace = "transactional-visibility"
	keys := make([]Key, memoryShardCount)
	for shardIndex := range memoryShardCount {
		keys[shardIndex] = memoryKeysForShard(t, namespace, shardIndex, 1)[0]
		admitMemoryTestEntry(t.Context(), t, memory, newMemoryTestEntry(namespace, keys[shardIndex], nil))
	}
	memory.state.limitBytes = memory.state.retainedCharge.Load()
	var planBuffer [maxMemoryEvictionsPerWrite]memoryPlannedEviction
	plannedEntries := memory.planEvictions(32*1024, "", Key{}, planBuffer[:])
	assert.True(t, plannedEntries > 0)
	candidate := planBuffer[0].entry
	cache := memory.Namespace(candidate.namespace)
	reader, _, err := cache.Open(t.Context(), candidate.key)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
}

func TestMemoryConcurrentPlanPreservesPostPlanReference(t *testing.T) {
	memory := newMemoryTestCache(t)
	key := NewKey("concurrent-plan-reference")
	entry := newMemoryTestEntry("", key, []byte("value"))
	admitMemoryTestEntry(t.Context(), t, memory, entry)

	var firstPlan [maxMemoryEvictionsPerWrite]memoryPlannedEviction
	firstPlanSize := memory.planEvictions(entry.charge, "protected", Key{}, firstPlan[:])
	assert.Equal(t, 1, firstPlanSize)

	reader, _, err := memory.Open(t.Context(), key)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())

	var concurrentPlan [maxMemoryEvictionsPerWrite]memoryPlannedEviction
	concurrentPlanSize := memory.planEvictions(entry.charge, "protected", Key{}, concurrentPlan[:])
	assert.Equal(t, 0, concurrentPlanSize)

	memory.commitMemoryEvictionPlan(t.Context(), firstPlan[:firstPlanSize], 0)
	_, err = memory.Stat(t.Context(), key)
	assert.NoError(t, err)
}

func TestMemoryLargeEntryCanDisplaceSmallEntries(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 2, InflightLimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, memory.Close()) })
	cache := memory.Namespace("mixed-entry-sizes")
	for index := range 256 {
		writeMemoryTestEntry(t, cache, NewKey(fmt.Sprintf("small-%d", index)), nil, time.Hour)
	}
	largeKey := NewKey("large")
	writeMemoryTestEntry(t, cache, largeKey, make([]byte, 512*1024), time.Hour)

	reader, _, err := cache.Open(t.Context(), largeKey)
	assert.NoError(t, err)
	data, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	assert.Equal(t, 512*1024, len(data))
	assert.True(t, memory.state.hardLimitCharge.Load() <= memory.state.limitBytes)
}

func BenchmarkMemoryAdmissionAtCapacity(b *testing.B) {
	for _, entryCount := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("entries=%d", entryCount), func(b *testing.B) {
			expiresAt := time.Now().Add(time.Hour)
			memory := newMemoryBenchmarkCache(b, entryCount, expiresAt)
			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				admitMemoryTestEntry(b.Context(), b, memory, newMemoryBenchmarkEntry(entryCount+index, expiresAt))
			}
		})
	}
}

func BenchmarkMemoryParallelAdmissionAtCapacity(b *testing.B) {
	const entryCount = 10_000
	expiresAt := time.Now().Add(time.Hour)
	memory := newMemoryBenchmarkCache(b, entryCount, expiresAt)
	var nextKey atomic.Uint64
	var attempts atomic.Uint64
	var admittedCount atomic.Uint64
	nextKey.Store(entryCount)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			attempts.Add(1)
			index := int(nextKey.Add(1))
			admitted, err := memory.admit(b.Context(), newMemoryBenchmarkEntry(index, expiresAt))
			if err != nil {
				b.Error(err)
				return
			}
			if admitted {
				admittedCount.Add(1)
			}
		}
	})
	b.ReportMetric(100*float64(admittedCount.Load())/float64(attempts.Load()), "accepted-%")
}

func BenchmarkMemoryConfiguredCreateAtCapacity(b *testing.B) {
	for _, entryCount := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("entries=%d", entryCount), func(b *testing.B) {
			expiresAt := time.Now().Add(time.Hour)
			memory := newConfiguredMemoryBenchmarkCache(b, entryCount, expiresAt)
			headers := http.Header{"Content-Length": {"1"}}
			payload := []byte{1}
			b.ReportAllocs()
			b.ResetTimer()
			for index := range b.N {
				entry := newMemoryBenchmarkEntry(entryCount+index, expiresAt)
				writer, err := memory.Create(b.Context(), entry.key, headers, time.Hour, WithETag("benchmark"))
				assert.NoError(b, err)
				memoryTestWriter(b, writer)
				written, err := writer.Write(payload)
				assert.NoError(b, err)
				assert.Equal(b, len(payload), written)
				assert.NoError(b, writer.Close())
				shard := memory.shard("", entry.key)
				shard.mu.RLock()
				_, admitted := shard.entry("", entry.key)
				shard.mu.RUnlock()
				assert.True(b, admitted)
			}
		})
	}
}

func newMemoryBenchmarkCache(b *testing.B, entryCount int, expiresAt time.Time) *Memory {
	b.Helper()
	state, err := newMemoryState(MemoryConfig{})
	assert.NoError(b, err)
	state.retainedTarget = int64(entryCount * memoryEntryMinimumCharge)
	state.limitBytes = state.retainedTarget + memoryEntryMinimumCharge
	memory := &Memory{state: state}
	for index := range entryCount {
		admitMemoryTestEntry(b.Context(), b, memory, newMemoryBenchmarkEntry(index, expiresAt))
	}
	return memory
}

func newConfiguredMemoryBenchmarkCache(b *testing.B, entryCount int, expiresAt time.Time) *Memory {
	b.Helper()
	config := MemoryConfig{LimitMB: 8, InflightLimitMB: 2, MaxTTL: time.Hour}
	state, err := newMemoryState(config)
	assert.NoError(b, err)
	state.retainedTarget = int64(entryCount * memoryEntryMinimumCharge)
	state.limitBytes = state.retainedTarget + 1024*1024
	memory := &Memory{config: config, state: state}
	for index := range entryCount {
		admitMemoryTestEntry(b.Context(), b, memory, newMemoryBenchmarkEntry(index, expiresAt))
	}
	return memory
}

func newMemoryBenchmarkEntry(index int, expiresAt time.Time) *memoryEntry {
	var key Key
	binary.LittleEndian.PutUint64(key[:8], uint64(index))
	entry := &memoryEntry{namespace: "benchmark", key: key, data: []byte{1}, expiresAt: expiresAt}
	entry.charge = memoryEntryCharge(entry.namespace, entry.data, nil)
	return entry
}

func BenchmarkMemoryParallelHotHits(b *testing.B) {
	_, ctx := logging.Configure(b.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 1, MaxTTL: time.Hour})
	assert.NoError(b, err)
	key := NewKey("parallel-hot-hit")
	writer, err := memory.Create(ctx, key, http.Header{"Content-Length": {"1"}}, time.Hour)
	assert.NoError(b, err)
	_, err = writer.Write([]byte{1})
	assert.NoError(b, err)
	assert.NoError(b, writer.Close())
	b.Cleanup(func() { assert.NoError(b, memory.Close()) })
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader, _, err := memory.Open(ctx, key)
			if err != nil {
				b.Error(err)
				return
			}
			if err := reader.Close(); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkMemoryParallelHotHitWriteToDiscard(b *testing.B) {
	_, ctx := logging.Configure(b.Context(), logging.Config{Level: slog.LevelError})
	memory, err := NewMemory(ctx, MemoryConfig{LimitMB: 8, MaxTTL: time.Hour})
	assert.NoError(b, err)
	key := NewKey("parallel-hot-hit-copy")
	payload := bytes.Repeat([]byte{0x4d}, 1024*1024)
	writer, err := memory.Create(ctx, key, http.Header{"Content-Length": {strconv.Itoa(len(payload))}}, time.Hour)
	assert.NoError(b, err)
	_, err = writer.Write(payload)
	assert.NoError(b, err)
	assert.NoError(b, writer.Close())
	b.Cleanup(func() { assert.NoError(b, memory.Close()) })
	b.ReportAllocs()
	b.ResetTimer()
	destination := writeOnlyDiscard{}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader, _, err := memory.Open(ctx, key)
			if err != nil {
				b.Error(err)
				return
			}
			if _, err := io.Copy(destination, reader); err != nil {
				b.Error(err)
				return
			}
			if err := reader.Close(); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
