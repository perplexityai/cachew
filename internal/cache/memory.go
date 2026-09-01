package cache

import (
	"context"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/logging"
)

const (
	memoryShardCount               = 16
	maxMemoryEvictionsPerWrite     = 64
	maxMemoryEvictionScansPerShard = 64
	maxMemoryReservationRetries    = 8
	memoryEntryMinimumCharge       = 4 * 1024
	memoryEntryBaseCharge          = 512
	memoryHeaderEntryCharge        = 64
	memoryHeaderValueCharge        = 16
	memoryWriterMinimumCharge      = 4 * 1024
	memoryWriterInitialCapacity    = memoryWriterMinimumCharge
	memoryBytesPerMegabyte         = 1024 * 1024
	fnv64Offset                    = 14695981039346656037
	fnv64Prime                     = 1099511628211
)

// RegisterMemory preserves the existing "memory" HCL backend while replacing its admission policy.
func RegisterMemory(r *Registry) {
	Register(
		r,
		"memory",
		"Caches objects in memory, with retained-size accounting and bounded CLOCK eviction",
		NewMemory,
	)
}

// MemoryConfig keeps incomplete-write protection opt-in so existing zero-valued configurations remain compatible.
type MemoryConfig struct {
	LimitMB         int           `hcl:"limit-mb,optional" help:"Maximum accounted memory in megabytes (defaults to 1GB, 0 is unlimited); positive inflight-limit-mb shares this budget." default:"1024"`
	InflightLimitMB int           `hcl:"inflight-limit-mb,optional" help:"Maximum aggregate incomplete writes in megabytes (0 disables the sub-limit); must be smaller than a finite limit-mb." default:"0"`
	MaxTTL          time.Duration `hcl:"max-ttl,optional" help:"Maximum time-to-live for entries in the memory cache (defaults to 1 hour)." default:"1h"`
}

type memoryEntry struct {
	namespace      Namespace
	key            Key
	data           []byte
	expiresAt      time.Time
	headers        http.Header
	charge         int64
	referenceEpoch atomic.Uint64
	clockEpoch     uint64
	readers        atomic.Int64
	previous       *memoryEntry
	next           *memoryEntry
	retired        atomic.Bool
	released       bool
}

type memoryShard struct {
	mu           sync.RWMutex
	entries      map[Namespace]map[Key]*memoryEntry
	evictionHead *memoryEntry
	evictionTail *memoryEntry
	evictionHand *memoryEntry
}

func (s *memoryShard) entry(namespace Namespace, key Key) (*memoryEntry, bool) {
	namespaceEntries, ok := s.entries[namespace]
	if !ok {
		return nil, false
	}
	entry, ok := namespaceEntries[key]
	return entry, ok
}

func (s *memoryShard) append(entry *memoryEntry) {
	entry.previous = s.evictionTail
	entry.next = nil
	if s.evictionTail == nil {
		s.evictionHead = entry
	} else {
		s.evictionTail.next = entry
	}
	s.evictionTail = entry
	if s.evictionHand == nil {
		s.evictionHand = entry
	}
}

func (s *memoryShard) remove(entry *memoryEntry) {
	nextHand := entry.next
	if entry.previous == nil {
		s.evictionHead = entry.next
	} else {
		entry.previous.next = entry.next
	}
	if entry.next == nil {
		s.evictionTail = entry.previous
	} else {
		entry.next.previous = entry.previous
	}
	entry.previous = nil
	entry.next = nil
	if s.evictionHand == entry {
		s.evictionHand = nextHand
		if s.evictionHand == nil {
			s.evictionHand = s.evictionHead
		}
	}
}

func (s *memoryShard) insert(entry *memoryEntry) {
	namespaceEntries := s.entries[entry.namespace]
	if namespaceEntries == nil {
		namespaceEntries = make(map[Key]*memoryEntry)
		s.entries[entry.namespace] = namespaceEntries
	}
	namespaceEntries[entry.key] = entry
	s.append(entry)
}

// With finite limits, the hard-budget counter overlaps retained and inflight
// charges only when an inflight sub-limit is configured, preventing independent
// reservations from crossing the process-wide accounting ceiling.
type memoryState struct {
	shards          []memoryShard
	limitBytes      int64
	retainedTarget  int64
	inflightLimit   int64
	retainedCharge  atomic.Int64
	inflightCharge  atomic.Int64
	hardLimitCharge atomic.Int64
	payloadSize     atomic.Int64
	objectCount     atomic.Int64
	evictionCursor  atomic.Uint32
	closed          atomic.Bool
	metrics         memoryMetricRecorder
}

// Memory shares capacity across namespace views so each view cannot consume limit-mb independently.
type Memory struct {
	config    MemoryConfig
	namespace Namespace
	state     *memoryState
}

func memoryMegabytes(field string, value int) (int64, error) {
	if value < 0 {
		return 0, errors.Errorf("%s must be non-negative", field)
	}
	if int64(value) > math.MaxInt64/memoryBytesPerMegabyte {
		return 0, errors.Errorf("%s is too large", field)
	}
	return int64(value) * memoryBytesPerMegabyte, nil
}

func newMemoryState(config MemoryConfig) (*memoryState, error) {
	limitBytes, err := memoryMegabytes("limit-mb", config.LimitMB)
	if err != nil {
		return nil, err
	}
	configuredInflightBytes, err := memoryMegabytes("inflight-limit-mb", config.InflightLimitMB)
	if err != nil {
		return nil, err
	}
	if limitBytes > 0 && configuredInflightBytes >= limitBytes {
		return nil, errors.New("inflight-limit-mb must be less than limit-mb when limit-mb is finite")
	}
	retainedTarget := int64(0)
	if limitBytes > 0 {
		retainedTarget = limitBytes - configuredInflightBytes
	}
	shards := make([]memoryShard, memoryShardCount)
	for index := range shards {
		shards[index].entries = make(map[Namespace]map[Key]*memoryEntry)
	}
	return &memoryState{
		shards: shards, limitBytes: limitBytes,
		retainedTarget: retainedTarget, inflightLimit: configuredInflightBytes,
		metrics: newMemoryMetrics(),
	}, nil
}

// NewMemory rejects invalid byte conversions before a bad limit can silently become unlimited.
func NewMemory(ctx context.Context, config MemoryConfig) (*Memory, error) {
	state, err := newMemoryState(config)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	logging.FromContext(ctx).InfoContext(ctx, "Constructing in-memory Cache", "limit-mb", config.LimitMB,
		"inflight-limit-mb", config.InflightLimitMB, "max-ttl", config.MaxTTL)
	return &Memory{config: config, state: state}, nil
}

func memoryShardIndex(namespace Namespace, key Key) int {
	hash := uint64(fnv64Offset)
	for index := range len(namespace) {
		hash ^= uint64(namespace[index])
		hash *= fnv64Prime
	}
	hash ^= 0xff
	hash *= fnv64Prime
	for _, value := range key {
		hash ^= uint64(value)
		hash *= fnv64Prime
	}
	return int(hash % memoryShardCount)
}

func (m *Memory) shard(namespace Namespace, key Key) *memoryShard {
	return &m.state.shards[memoryShardIndex(namespace, key)]
}

func expectedContentLength(headers http.Header) int64 {
	contentLength, err := strconv.ParseInt(headers.Get("Content-Length"), 10, 64)
	if err != nil || contentLength < 0 {
		return -1
	}
	return contentLength
}

func memoryMetadataCharge(namespace Namespace, headers http.Header) int64 {
	charge := int64(memoryEntryBaseCharge + len(namespace))
	for name, values := range headers {
		charge += int64(memoryHeaderEntryCharge + len(name))
		for _, value := range values {
			charge += int64(memoryHeaderValueCharge + len(value))
		}
	}
	return charge
}

func memoryEntryCharge(namespace Namespace, data []byte, headers http.Header) int64 {
	charge := int64(cap(data)) + memoryMetadataCharge(namespace, headers)
	return max(charge, int64(memoryEntryMinimumCharge))
}

func reserveBounded(counter *atomic.Int64, limit, amount int64) bool {
	if amount <= 0 {
		return true
	}
	for range maxMemoryReservationRetries {
		current := counter.Load()
		if amount > limit-current {
			return false
		}
		if counter.CompareAndSwap(current, current+amount) {
			return true
		}
	}
	return false
}

type memoryPlannedEviction struct {
	shard          *memoryShard
	entry          *memoryEntry
	referenceEpoch uint64
}

func (m *Memory) releaseRetiredLocked(entry *memoryEntry) {
	if entry.released || !entry.retired.Load() || entry.readers.Load() != 0 {
		return
	}
	entry.released = true
	m.state.retainedCharge.Add(-entry.charge)
	m.state.hardLimitCharge.Add(-entry.charge)
	entry.data = nil
	entry.headers = nil
}

func (m *Memory) removeActiveLocked(shard *memoryShard, entry *memoryEntry) {
	shard.remove(entry)
	namespaceEntries := shard.entries[entry.namespace]
	delete(namespaceEntries, entry.key)
	if len(namespaceEntries) == 0 {
		delete(shard.entries, entry.namespace)
	}
	entry.retired.Store(true)
	m.state.objectCount.Add(-1)
	m.state.payloadSize.Add(-int64(len(entry.data)))
	m.releaseRetiredLocked(entry)
}

func (m *Memory) replaceActiveLocked(shard *memoryShard, oldEntry, newEntry *memoryEntry) {
	oldPayloadSize := len(oldEntry.data)
	shard.remove(oldEntry)
	oldEntry.retired.Store(true)
	oldEntry.released = true
	oldEntry.data = nil
	oldEntry.headers = nil
	shard.entries[newEntry.namespace][newEntry.key] = newEntry
	shard.append(newEntry)
	m.state.payloadSize.Add(int64(len(newEntry.data) - oldPayloadSize))
}

func (m *Memory) insertActiveLocked(shard *memoryShard, entry *memoryEntry) {
	shard.insert(entry)
	m.state.objectCount.Add(1)
	m.state.payloadSize.Add(int64(len(entry.data)))
}

func (m *Memory) reserveRetained(retainedLimit, amount int64) bool {
	if m.state.limitBytes == 0 {
		m.state.retainedCharge.Add(amount)
		m.state.hardLimitCharge.Add(amount)
		return true
	}
	if !reserveBounded(&m.state.retainedCharge, retainedLimit, amount) {
		return false
	}
	if reserveBounded(&m.state.hardLimitCharge, m.state.limitBytes, amount) {
		return true
	}
	m.state.retainedCharge.Add(-amount)
	return false
}

type memoryAdmissionMode uint8

const (
	memoryAdmissionNeedsAllocation memoryAdmissionMode = iota
	memoryAdmissionHasAllocation
)

func (m *Memory) reserveAdmission(mode memoryAdmissionMode, retainedLimit, amount int64) bool {
	if mode == memoryAdmissionHasAllocation {
		if m.state.limitBytes == 0 {
			m.state.retainedCharge.Add(amount)
			return true
		}
		return reserveBounded(&m.state.retainedCharge, retainedLimit, amount)
	}
	return m.reserveRetained(retainedLimit, amount)
}

func (m *Memory) tryAdmission(
	ctx context.Context,
	entry *memoryEntry,
	retainedLimit int64,
	mode memoryAdmissionMode,
) (bool, error) {
	shard := m.shard(entry.namespace, entry.key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if m.state.closed.Load() {
		return false, errors.WithStack(os.ErrClosed)
	}
	if err := ctx.Err(); err != nil {
		return false, errors.WithStack(err)
	}
	oldEntry, replacing := shard.entry(entry.namespace, entry.key)
	if replacing && oldEntry.readers.Load() == 0 {
		delta := entry.charge - oldEntry.charge
		if delta > 0 && !m.reserveAdmission(mode, retainedLimit, delta) {
			return false, nil
		}
		m.replaceActiveLocked(shard, oldEntry, entry)
		if delta < 0 {
			m.state.retainedCharge.Add(delta)
		}
		if mode == memoryAdmissionHasAllocation {
			m.state.hardLimitCharge.Add(-oldEntry.charge)
		} else if delta < 0 {
			m.state.hardLimitCharge.Add(delta)
		}
		return true, nil
	}
	if !m.reserveAdmission(mode, retainedLimit, entry.charge) {
		return false, nil
	}
	if oldEntry != nil {
		m.removeActiveLocked(shard, oldEntry)
	}
	m.insertActiveLocked(shard, entry)
	return true, nil
}

func (m *Memory) admitReserved(ctx context.Context, entry *memoryEntry) (bool, error) {
	if m.state.closed.Load() {
		return false, errors.WithStack(os.ErrClosed)
	}
	if m.state.limitBytes > 0 && entry.charge > m.state.limitBytes {
		return false, nil
	}
	admitted, err := m.tryAdmission(ctx, entry, m.state.limitBytes, memoryAdmissionHasAllocation)
	if admitted || err != nil || m.state.limitBytes <= 0 {
		if admitted && m.state.limitBytes > 0 {
			m.trimToTarget(ctx, entry.namespace, entry.key)
		}
		return admitted, err
	}
	m.trimToTarget(ctx, entry.namespace, entry.key)
	admitted, err = m.tryAdmission(ctx, entry, m.state.limitBytes, memoryAdmissionHasAllocation)
	if admitted {
		m.trimToTarget(ctx, entry.namespace, entry.key)
	}
	return admitted, err
}

func (m *Memory) planEvictions(
	needed int64,
	protectedNamespace Namespace,
	protectedKey Key,
	planned []memoryPlannedEviction,
) int {
	// Planning leaves candidates visible to readers. The later commit phase
	// revalidates each reference epoch so a hit between these phases wins its
	// CLOCK second chance without holding multiple shard locks at once.
	if needed <= 0 {
		return 0
	}
	now := time.Now()
	start := int((m.state.evictionCursor.Add(1) - 1) % memoryShardCount)
	plannedEntries := 0
	plannedSize := int64(0)
	for offset := range memoryShardCount {
		shard := &m.state.shards[(start+offset)%memoryShardCount]
		shard.mu.Lock()
		scanned := 0
		candidate := shard.evictionHand
		startCandidate := candidate
		for candidate != nil && scanned < maxMemoryEvictionScansPerShard {
			scanned++
			nextCandidate := candidate.next
			if nextCandidate == nil {
				nextCandidate = shard.evictionHead
			}
			if candidate.namespace != protectedNamespace || candidate.key != protectedKey {
				referenceEpoch := candidate.referenceEpoch.Load()
				expired := !now.Before(candidate.expiresAt)
				if candidate.readers.Load() == 0 {
					if expired || candidate.clockEpoch == referenceEpoch {
						planned[plannedEntries] = memoryPlannedEviction{
							shard: shard, entry: candidate, referenceEpoch: referenceEpoch,
						}
						plannedEntries++
						plannedSize += candidate.charge
					} else {
						candidate.clockEpoch = referenceEpoch
					}
				}
			}
			candidate = nextCandidate
			if plannedSize >= needed || plannedEntries == maxMemoryEvictionsPerWrite || candidate == startCandidate {
				break
			}
		}
		shard.evictionHand = candidate
		shard.mu.Unlock()
		if plannedSize >= needed || plannedEntries == maxMemoryEvictionsPerWrite {
			break
		}
	}
	return plannedEntries
}

func (m *Memory) commitMemoryEvictionPlan(ctx context.Context, planned []memoryPlannedEviction, target int64) {
	// Pointer identity rejects replacements and the epoch check rejects
	// post-plan hits, so only the exact cold generation originally planned can
	// be removed.
	now := time.Now()
	for start := 0; start < len(planned); {
		shard := planned[start].shard
		shard.mu.Lock()
		if ctx.Err() != nil {
			shard.mu.Unlock()
			return
		}
		end := start
		for end < len(planned) && planned[end].shard == shard {
			if m.state.retainedCharge.Load() <= target {
				shard.mu.Unlock()
				return
			}
			plannedEntry := planned[end]
			entry := plannedEntry.entry
			activeEntry, active := shard.entry(entry.namespace, entry.key)
			if active && activeEntry == entry && entry.readers.Load() == 0 {
				referenceEpoch := entry.referenceEpoch.Load()
				if !now.Before(entry.expiresAt) || referenceEpoch == plannedEntry.referenceEpoch {
					m.removeActiveLocked(shard, entry)
				} else {
					entry.clockEpoch = referenceEpoch
				}
			}
			end++
		}
		shard.mu.Unlock()
		start = end
	}
}

func (m *Memory) trimToTarget(ctx context.Context, protectedNamespace Namespace, protectedKey Key) {
	needed := m.state.retainedCharge.Load() - m.state.retainedTarget
	if needed <= 0 {
		return
	}
	var planBuffer [maxMemoryEvictionsPerWrite]memoryPlannedEviction
	plannedEntries := m.planEvictions(needed, protectedNamespace, protectedKey, planBuffer[:])
	m.commitMemoryEvictionPlan(ctx, planBuffer[:plannedEntries], m.state.retainedTarget)
}

func (m *Memory) trimForAdmission(ctx context.Context, entry *memoryEntry) {
	amount := entry.charge
	shard := m.shard(entry.namespace, entry.key)
	shard.mu.RLock()
	if oldEntry, replacing := shard.entry(entry.namespace, entry.key); replacing && oldEntry.readers.Load() == 0 {
		amount = max(entry.charge-oldEntry.charge, 0)
	}
	shard.mu.RUnlock()
	target := max(m.state.limitBytes-amount, 0)
	needed := m.state.retainedCharge.Load() - target
	if needed <= 0 {
		return
	}
	var planBuffer [maxMemoryEvictionsPerWrite]memoryPlannedEviction
	plannedEntries := m.planEvictions(needed, entry.namespace, entry.key, planBuffer[:])
	m.commitMemoryEvictionPlan(ctx, planBuffer[:plannedEntries], target)
}

func (m *Memory) admit(ctx context.Context, entry *memoryEntry) (bool, error) {
	if m.state.closed.Load() {
		return false, errors.WithStack(os.ErrClosed)
	}
	if m.state.limitBytes > 0 && entry.charge > m.state.limitBytes {
		return false, nil
	}
	admitted, err := m.tryAdmission(ctx, entry, m.state.retainedTarget, memoryAdmissionNeedsAllocation)
	if err != nil || m.state.limitBytes <= 0 {
		return admitted, err
	}
	if admitted {
		m.trimToTarget(ctx, entry.namespace, entry.key)
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, errors.WithStack(err)
	}
	m.trimForAdmission(ctx, entry)
	admitted, err = m.tryAdmission(ctx, entry, m.state.limitBytes, memoryAdmissionNeedsAllocation)
	if !admitted || err != nil {
		return admitted, err
	}
	m.trimToTarget(ctx, entry.namespace, entry.key)
	return true, nil
}

// String includes the hard limit so differently sized tiers remain distinguishable in diagnostics.
func (m *Memory) String() string { return fmt.Sprintf("memory:%dMB", m.config.LimitMB) }

func (m *Memory) backendType() BackendType { return backendMemory }

// Stat counts metadata-only hits as CLOCK references so they receive the same recency protection as Open.
func (m *Memory) Stat(_ context.Context, key Key, opts ...Option) (http.Header, error) {
	shard := m.shard(m.namespace, key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.entry(m.namespace, key)
	if !exists || time.Now().After(entry.expiresAt) {
		return nil, os.ErrNotExist
	}
	entry.referenceEpoch.Add(1)

	headers := maps.Clone(entry.headers)
	headers.Set("Content-Length", strconv.Itoa(len(entry.data)))
	if h, err := conditionalShortCircuit(headers, opts); err != nil {
		return h, err
	}
	return headers, nil
}

// Open pins its entry generation so replacement and eviction cannot invalidate an active response body.
func (m *Memory) Open(_ context.Context, key Key, opts ...Option) (io.ReadCloser, http.Header, error) {
	shard := m.shard(m.namespace, key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.entry(m.namespace, key)
	if !exists || time.Now().After(entry.expiresAt) {
		return nil, nil, os.ErrNotExist
	}
	entry.referenceEpoch.Add(1)

	headers := maps.Clone(entry.headers)
	headers.Set("Content-Length", strconv.Itoa(len(entry.data)))
	if h, err := conditionalShortCircuit(headers, opts); err != nil {
		return nil, h, err
	}

	start, length, partial, rangeErr := rangeShortCircuit(headers, int64(len(entry.data)), opts)
	if rangeErr != nil {
		return nil, headers, rangeErr
	}
	data := entry.data
	if partial {
		data = data[start : start+length]
	}
	entry.readers.Add(1)
	return &memoryReader{data: data, cache: m, shard: shard, entry: entry}, headers, nil
}

type memoryReader struct {
	data   []byte
	offset int
	cache  *Memory
	shard  *memoryShard
	entry  *memoryEntry
	closed atomic.Bool
}

var _ io.WriterTo = (*memoryReader)(nil)

func (r *memoryReader) Read(p []byte) (int, error) {
	if r.closed.Load() {
		return 0, os.ErrClosed
	}
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *memoryReader) WriteTo(destination io.Writer) (int64, error) {
	if r.closed.Load() {
		return 0, os.ErrClosed
	}
	if r.offset >= len(r.data) {
		return 0, nil
	}
	remaining := len(r.data) - r.offset
	written, err := destination.Write(r.data[r.offset:])
	if written < 0 || written > remaining {
		return 0, errors.Errorf("invalid Write count %d", written)
	}
	r.offset += written
	if written != remaining && err == nil {
		err = io.ErrShortWrite
	}
	return int64(written), errors.WithStack(err)
}

func (r *memoryReader) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	r.data = nil
	if r.entry.readers.Add(-1) != 0 || !r.entry.retired.Load() {
		return nil
	}
	r.shard.mu.Lock()
	r.cache.releaseRetiredLocked(r.entry)
	r.shard.mu.Unlock()
	return nil
}

// Create buffers privately so incomplete bodies stay invisible and declined memory admission remains non-fatal.
func (m *Memory) Create(ctx context.Context, key Key, headers http.Header, ttl time.Duration, opts ...Option) (Writer, error) {
	if m.state.closed.Load() {
		return nil, errors.WithStack(os.ErrClosed)
	}
	if ttl == 0 {
		ttl = m.config.MaxTTL
	}

	now := time.Now()
	contentLength := expectedContentLength(headers)
	clonedHeaders := httputil.FilterHeaders(headers, httputil.TransportHeaders...)
	if clonedHeaders.Get("Last-Modified") == "" {
		clonedHeaders.Set("Last-Modified", now.UTC().Format(http.TimeFormat))
	}
	if err := setCreateETag(clonedHeaders, opts...); err != nil {
		return nil, err
	}

	metadataCharge := memoryMetadataCharge(m.namespace, clonedHeaders)
	baseCharge := max(metadataCharge, int64(memoryWriterMinimumCharge))
	if contentLength >= 0 && m.state.limitBytes > 0 && contentLength > m.state.limitBytes-metadataCharge {
		m.state.metrics.recordDecline(ctx, memoryDeclineDeclaredHardLimit)
		return &noOpWriter{}, nil
	}
	if contentLength >= 0 && m.state.inflightLimit > 0 && contentLength > m.state.inflightLimit-baseCharge {
		m.state.metrics.recordDecline(ctx, memoryDeclineDeclaredInflightLimit)
		return &noOpWriter{}, nil
	}
	ctx, cancel := context.WithCancelCause(ctx)
	writer := &memoryWriter{
		cache:          m,
		namespace:      m.namespace,
		key:            key,
		expiresAt:      now.Add(ttl),
		headers:        clonedHeaders,
		limitBytes:     m.state.limitBytes,
		inflightLimit:  m.state.inflightLimit,
		budgeted:       m.state.inflightLimit > 0,
		baseCharge:     baseCharge,
		expectedLength: contentLength,
		ctx:            ctx,
		cancel:         cancel,
	}
	if !writer.reserve(baseCharge) {
		m.state.metrics.recordDecline(ctx, memoryDeclineWriterReservation)
		cancel(nil)
		return &noOpWriter{}, nil
	}
	return writer, nil
}

// Delete defers reclaiming reader-pinned storage until the final reader closes.
func (m *Memory) Delete(_ context.Context, key Key) error {
	shard := m.shard(m.namespace, key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if m.state.closed.Load() {
		return errors.WithStack(os.ErrClosed)
	}

	entry, exists := shard.entry(m.namespace, key)
	if !exists {
		return os.ErrNotExist
	}
	m.removeActiveLocked(shard, entry)
	return nil
}

// Invalidate treats a missing entry as success because callers use it to discard optional stale copies.
func (m *Memory) Invalidate(ctx context.Context, key Key) error {
	err := m.Delete(ctx, key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.WithStack(err)
}

// Close stops admission immediately while reader-pinned generations remain valid until their readers close.
func (m *Memory) Close() error {
	if !m.state.closed.CompareAndSwap(false, true) {
		return nil
	}
	for index := range m.state.shards {
		shard := &m.state.shards[index]
		shard.mu.Lock()
		for shard.evictionHead != nil {
			m.removeActiveLocked(shard, shard.evictionHead)
		}
		shard.entries = make(map[Namespace]map[Key]*memoryEntry)
		shard.mu.Unlock()
	}
	return nil
}

// Stats uses atomics so metrics collection never waits behind cache traffic on a shard lock.
func (m *Memory) Stats(_ context.Context) (Stats, error) {
	return Stats{
		Objects:  m.state.objectCount.Load(),
		Size:     m.state.payloadSize.Load(),
		Capacity: m.state.limitBytes,
	}, nil
}

type memoryWriter struct {
	cache          *Memory
	namespace      Namespace
	key            Key
	data           []byte
	expiresAt      time.Time
	headers        http.Header
	limitBytes     int64
	inflightLimit  int64
	budgeted       bool
	baseCharge     int64
	reservedBytes  int64
	expectedLength int64
	discarded      bool
	closed         bool
	ctx            context.Context
	cancel         context.CancelCauseFunc
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("writer closed")
	}
	if w.discarded {
		return len(p), nil
	}
	buffered := int64(len(w.data))
	tooLarge := w.limitBytes > 0 && int64(len(p)) > w.limitBytes-w.baseCharge-buffered
	longerThanDeclared := w.expectedLength >= 0 && int64(len(p)) > w.expectedLength-buffered
	needed := buffered + int64(len(p))
	if tooLarge {
		w.decline(memoryDeclineBodyHardLimit)
		return len(p), nil
	}
	if longerThanDeclared {
		w.decline(memoryDeclineContentLengthMismatch)
		return len(p), nil
	}
	if !w.ensureCapacity(needed) {
		w.decline(memoryDeclineWriterReservation)
		return len(p), nil
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

func memoryBufferCapacity(size int64) (int, bool) {
	capacity := int(size)
	return capacity, capacity >= 0 && int64(capacity) == size
}

func (w *memoryWriter) maximumBodyCapacity() int64 {
	maximum := int64(math.MaxInt64)
	if w.limitBytes > 0 {
		maximum = min(maximum, w.limitBytes-w.baseCharge)
	}
	if w.inflightLimit > 0 {
		maximum = min(maximum, w.inflightLimit-w.baseCharge)
	}
	if w.expectedLength >= 0 {
		maximum = min(maximum, w.expectedLength)
	}
	return maximum
}

func (w *memoryWriter) nextCapacity(needed int64) (int64, bool) {
	maximum := w.maximumBodyCapacity()
	if needed < 0 || needed > maximum {
		return 0, false
	}
	current := int64(cap(w.data))
	initial := min(int64(memoryWriterInitialCapacity), maximum)
	if w.expectedLength >= 0 {
		initial = min(initial, w.expectedLength)
	}
	next := max(needed, initial)
	if current > 0 {
		doubled := maximum
		if current <= maximum-current {
			doubled = current * 2
		}
		next = max(next, min(doubled, maximum))
	}
	return next, true
}

func (w *memoryWriter) ensureCapacity(needed int64) bool {
	if needed <= int64(cap(w.data)) {
		return true
	}
	next, ok := w.nextCapacity(needed)
	if !ok {
		return false
	}
	oldCapacity := int64(cap(w.data))
	additionalCapacity := next - oldCapacity
	if !w.reserve(additionalCapacity) {
		return false
	}
	capacity, ok := memoryBufferCapacity(next)
	if !ok {
		w.release(additionalCapacity)
		return false
	}
	grown := make([]byte, len(w.data), capacity)
	copy(grown, w.data)
	w.data = grown
	return true
}

func (w *memoryWriter) reserve(amount int64) bool {
	if amount <= 0 {
		return true
	}
	if w.tryReserve(amount) {
		return true
	}
	if !w.budgeted {
		return false
	}
	w.cache.trimToTarget(w.ctx, w.namespace, w.key)
	return w.tryReserve(amount)
}

func (w *memoryWriter) tryReserve(amount int64) bool {
	if w.inflightLimit == 0 {
		w.cache.state.inflightCharge.Add(amount)
	} else if !reserveBounded(&w.cache.state.inflightCharge, w.inflightLimit, amount) {
		return false
	}
	if w.budgeted {
		if w.limitBytes == 0 {
			w.cache.state.hardLimitCharge.Add(amount)
		} else if !reserveBounded(&w.cache.state.hardLimitCharge, w.limitBytes, amount) {
			w.cache.state.inflightCharge.Add(-amount)
			return false
		}
	}
	w.reservedBytes += amount
	return true
}

func (w *memoryWriter) release(amount int64) {
	if amount <= 0 {
		return
	}
	w.cache.state.inflightCharge.Add(-amount)
	if w.budgeted {
		w.cache.state.hardLimitCharge.Add(-amount)
	}
	w.reservedBytes -= amount
}

func (w *memoryWriter) releaseReservation() {
	if w.reservedBytes > 0 {
		w.cache.state.inflightCharge.Add(-w.reservedBytes)
		if w.budgeted {
			w.cache.state.hardLimitCharge.Add(-w.reservedBytes)
		}
		w.reservedBytes = 0
	}
}

func (w *memoryWriter) transferReservation(charge int64) {
	w.cache.state.inflightCharge.Add(-w.reservedBytes)
	if excess := w.reservedBytes - charge; excess > 0 {
		w.cache.state.hardLimitCharge.Add(-excess)
	}
	w.reservedBytes = 0
}

func (w *memoryWriter) discard() {
	w.releaseReservation()
	w.data = nil
	w.discarded = true
}

func (w *memoryWriter) decline(reason memoryDeclineReason) {
	if w.discarded {
		return
	}
	w.cache.state.metrics.recordDecline(w.ctx, reason)
	w.discard()
}

func (w *memoryWriter) Abort(err error) error {
	w.cancel(err)
	return w.Close()
}

func (w *memoryWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.releaseReservation()
	if err := w.ctx.Err(); err != nil {
		w.discard()
		return errors.Wrap(err, "create operation cancelled")
	}
	if w.discarded {
		return nil
	}
	if w.expectedLength >= 0 && int64(len(w.data)) != w.expectedLength {
		w.decline(memoryDeclineContentLengthMismatch)
		return nil
	}

	data := w.data
	w.data = nil
	entry := &memoryEntry{
		namespace: w.namespace,
		key:       w.key,
		data:      data,
		expiresAt: w.expiresAt,
		headers:   w.headers,
	}
	entry.charge = memoryEntryCharge(entry.namespace, entry.data, entry.headers)
	if !w.budgeted {
		admitted, err := w.cache.admit(w.ctx, entry)
		if !admitted && err == nil {
			w.cache.state.metrics.recordDecline(w.ctx, memoryDeclineAdmissionLimit)
		}
		return errors.WithStack(err)
	}
	if entry.charge > w.reservedBytes && !w.reserve(entry.charge-w.reservedBytes) {
		w.cache.state.metrics.recordDecline(w.ctx, memoryDeclineWriterReservation)
		return nil
	}
	admitted, err := w.cache.admitReserved(w.ctx, entry)
	if admitted {
		w.transferReservation(entry.charge)
	} else if err == nil {
		w.cache.state.metrics.recordDecline(w.ctx, memoryDeclineAdmissionLimit)
	}
	return errors.WithStack(err)
}

// Namespace reuses one state object so every protocol namespace shares the configured capacity.
func (m *Memory) Namespace(namespace Namespace) Cache {
	view := *m
	view.namespace = namespace
	return &view
}

// ListNamespaces excludes the default namespace because only explicit cache partitions are discoverable.
func (m *Memory) ListNamespaces(_ context.Context) ([]string, error) {
	namespaces := make(map[Namespace]struct{})
	for index := range m.state.shards {
		shard := &m.state.shards[index]
		shard.mu.RLock()
		for namespace, namespaceEntries := range shard.entries {
			if namespace != "" && len(namespaceEntries) > 0 {
				namespaces[namespace] = struct{}{}
			}
		}
		shard.mu.RUnlock()
	}

	result := make([]string, 0, len(namespaces))
	for namespace := range namespaces {
		result = append(result, string(namespace))
	}
	return result, nil
}
