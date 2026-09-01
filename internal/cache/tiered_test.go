package cache_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/cache/cachetest"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/s3client"
	"github.com/block/cachew/internal/s3client/s3clienttest"
)

// seedTier writes content to a single tier directly, so tests can diverge the
// versions held by each tier.
func seedTier(ctx context.Context, t *testing.T, c cache.Cache, key cache.Key, content []byte, rawETag ...string) {
	t.Helper()
	var opts []cache.Option
	if len(rawETag) > 0 {
		opts = append(opts, cache.WithETag(rawETag[0]))
	}
	w, err := c.Create(ctx, key, nil, time.Minute, opts...)
	assert.NoError(t, err)
	_, err = w.Write(content)
	assert.NoError(t, err)
	assert.NoError(t, w.Close())
}

func readAllAndClose(t *testing.T, r io.ReadCloser) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.NoError(t, r.Close())
	return data
}

func newMetadataStore(ctx context.Context) *metadatadb.Store {
	return metadatadb.New(ctx, metadatadb.NewMemoryBackend())
}

func tieredETags(store *metadatadb.Store, namespace cache.Namespace) *metadatadb.Map[cache.Key, string] {
	return metadatadb.NewMap[cache.Key, string](store.Namespace(string(namespace)), "cache-etags")
}

func newTiered(ctx context.Context, caches ...cache.Cache) cache.Cache {
	return cache.MaybeNewTiered(ctx, caches, newMetadataStore(ctx))
}

type failingCache struct {
	cache.Cache
	err error
}

func newFailingCache(err error) cache.Cache {
	return failingCache{Cache: cache.NoOpCache(), err: err}
}

func (c failingCache) String() string { return "failing" }

func (c failingCache) Stat(_ context.Context, _ cache.Key, _ ...cache.Option) (http.Header, error) {
	return nil, c.err
}

func (c failingCache) Open(_ context.Context, _ cache.Key, _ ...cache.Option) (io.ReadCloser, http.Header, error) {
	return nil, nil, c.err
}

type createFuncCache struct {
	cache.Cache
	create func(context.Context, cache.Key, http.Header, time.Duration, ...cache.Option) (cache.Writer, error)
}

func (c createFuncCache) Create(
	ctx context.Context,
	key cache.Key,
	headers http.Header,
	ttl time.Duration,
	opts ...cache.Option,
) (cache.Writer, error) {
	return c.create(ctx, key, headers, ttl, opts...)
}

type blockedCreateCache struct {
	cache.Cache
	started chan struct{}
	release chan struct{}
	creates atomic.Int32
	once    sync.Once
}

func (c *blockedCreateCache) Create(
	ctx context.Context,
	key cache.Key,
	headers http.Header,
	ttl time.Duration,
	opts ...cache.Option,
) (cache.Writer, error) {
	c.creates.Add(1)
	c.once.Do(func() { close(c.started) })
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return c.Cache.Create(ctx, key, headers, ttl, opts...)
}

func newRecordingNoOpWriter(t *testing.T, committed, aborted chan struct{}) cache.Writer {
	t.Helper()
	writer, err := cache.NoOpCache().Create(t.Context(), cache.NewKey("recording-noop"), nil, time.Hour)
	assert.NoError(t, err)
	return &recordingWriter{Writer: writer, committed: committed, aborted: aborted}
}

type statFailingCache struct {
	cache.Cache
	err error
}

func newStatFailingCache(c cache.Cache, err error) cache.Cache {
	return statFailingCache{Cache: c, err: err}
}

func (c statFailingCache) Stat(_ context.Context, _ cache.Key, _ ...cache.Option) (http.Header, error) {
	return nil, c.err
}

type cacheFactory struct {
	name string
	new  func(t *testing.T) cache.Cache
}

func tieredPermutations(t *testing.T) []struct {
	name    string
	lower   cacheFactory
	upper   cacheFactory
	cleanup func()
} {
	t.Helper()

	bucket := s3clienttest.Start(t)

	newMemory := cacheFactory{"Memory", func(t *testing.T) cache.Cache {
		t.Helper()
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		c, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
		assert.NoError(t, err)
		return c
	}}

	newDisk := cacheFactory{"Disk", func(t *testing.T) cache.Cache {
		t.Helper()
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		c, err := cache.NewDisk(ctx, cache.DiskConfig{Root: t.TempDir(), LimitMB: 1024, MaxTTL: time.Hour})
		assert.NoError(t, err)
		return c
	}}

	newS3 := cacheFactory{"S3", func(t *testing.T) cache.Cache {
		t.Helper()
		s3clienttest.CleanBucket(t, bucket)
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		clientProvider := s3client.NewClientProvider(ctx, s3client.Config{
			Endpoint: s3clienttest.Addr,
			UseSSL:   false,
		})
		c, err := cache.NewS3(ctx, cache.S3Config{
			Bucket:           bucket,
			MaxTTL:           3 * time.Second,
			UploadPartSizeMB: 16,
		}, clientProvider)
		assert.NoError(t, err)
		return c
	}}

	backends := []cacheFactory{newMemory, newDisk, newS3}
	var perms []struct {
		name    string
		lower   cacheFactory
		upper   cacheFactory
		cleanup func()
	}
	for _, lower := range backends {
		for _, upper := range backends {
			if lower.name == upper.name {
				continue
			}
			perms = append(perms, struct {
				name    string
				lower   cacheFactory
				upper   cacheFactory
				cleanup func()
			}{
				name:  fmt.Sprintf("%s+%s", lower.name, upper.name),
				lower: lower,
				upper: upper,
			})
		}
	}
	return perms
}

func tieredMemoryDiskPermutations() []struct {
	name  string
	lower cacheFactory
	upper cacheFactory
} {
	newMemory := cacheFactory{"Memory", func(t *testing.T) cache.Cache {
		t.Helper()
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		c, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
		assert.NoError(t, err)
		return c
	}}

	newDisk := cacheFactory{"Disk", func(t *testing.T) cache.Cache {
		t.Helper()
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		c, err := cache.NewDisk(ctx, cache.DiskConfig{Root: t.TempDir(), LimitMB: 1024, MaxTTL: time.Hour})
		assert.NoError(t, err)
		return c
	}}

	return []struct {
		name  string
		lower cacheFactory
		upper cacheFactory
	}{
		{name: "Memory+Disk", lower: newMemory, upper: newDisk},
		{name: "Disk+Memory", lower: newDisk, upper: newMemory},
	}
}

func TestTieredCachePermutations(t *testing.T) {
	for _, perm := range tieredMemoryDiskPermutations() {
		t.Run(perm.name, func(t *testing.T) {
			cachetest.Suite(t, func(t *testing.T) cache.Cache {
				_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
				lower := perm.lower.new(t)
				upper := perm.upper.new(t)
				return newTiered(ctx, lower, upper)
			}, cachetest.WithoutInvalidate())
		})
	}
}

func TestTieredBackfillPermutations(t *testing.T) {
	for _, perm := range tieredMemoryDiskPermutations() {
		t.Run(perm.name, func(t *testing.T) {
			_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
			lower := perm.lower.new(t)
			upper := perm.upper.new(t)
			tiered := newTiered(ctx, lower, upper)
			defer tiered.Close()

			key := cache.NewKey("backfill-test")
			content := []byte("hello backfill")
			etag := `"backfill-etag"`

			// Write only to upper tier, simulating a lower-tier miss.
			seedTier(ctx, t, upper, key, content, "backfill-etag")

			// Verify lower tier does not have it.
			_, _, err := lower.Open(ctx, key)
			assert.IsError(t, err, os.ErrNotExist)

			// Open through tiered — should hit upper and backfill lower.
			r, headers, source, err := cache.OpenWithTier(ctx, tiered, key)
			assert.NoError(t, err)
			assert.Equal(t, content, readAllAndClose(t, r))
			assert.Equal(t, etag, headers.Get(cache.ETagKey))
			assert.Equal(t, cache.BackendType(strings.ToLower(perm.upper.name)), source)

			eventually(t, func() bool { return tierHolds(ctx, t, lower, key, content, etag) })
		})
	}
}

func TestTieredBackfillCoalescesWithoutDelayingReads(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	lowerMemory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	lower := &blockedCreateCache{
		Cache:   lowerMemory,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(lower.release) }) }
	defer release()
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := newTiered(ctx, lower, upper)
	defer tiered.Close()

	key := cache.NewKey("coalesced-backfill")
	content := bytes.Repeat([]byte("backfill"), 1024)
	seedTier(ctx, t, upper, key, content, "coalesced-etag")

	opened := make(chan io.ReadCloser, 1)
	go func() {
		r, _, openErr := tiered.Open(ctx, key)
		if openErr == nil {
			opened <- r
			return
		}
		opened <- nil
	}()
	select {
	case <-lower.started:
	case <-time.After(2 * time.Second):
		t.Fatal("backfill writer creation did not start")
	}

	var readers []io.ReadCloser
	select {
	case r := <-opened:
		assert.NotZero(t, r)
		readers = append(readers, r)
	case <-time.After(2 * time.Second):
		t.Fatal("optional backfill delayed the cache hit")
	}
	for range 7 {
		r, _, err := tiered.Open(ctx, key)
		assert.NoError(t, err)
		readers = append(readers, r)
	}
	assert.Equal(t, int32(1), lower.creates.Load())

	release()
	for _, r := range readers {
		assert.Equal(t, content, readAllAndClose(t, r))
	}
	eventually(t, func() bool { return tierHolds(ctx, t, lowerMemory, key, content, `"coalesced-etag"`) })
}

func TestTieredBackfillDiscardsIncompleteStreams(t *testing.T) {
	errMidStream := errors.New("mid-stream failure")
	newTieredWithFailingUpper := func(t *testing.T, key cache.Key, content []byte, failAfter int) (tiered, lower cache.Cache) {
		t.Helper()
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
		assert.NoError(t, err)
		upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
		assert.NoError(t, err)
		seedTier(ctx, t, upper, key, content, "backfill-etag")
		tiered = newTiered(ctx, lower, midStreamFailingCache{Cache: upper, failAfter: failAfter, err: errMidStream})
		t.Cleanup(func() { _ = tiered.Close() })
		return tiered, lower
	}

	key := cache.NewKey("backfill-truncated")
	content := bytes.Repeat([]byte("0123456789abcdef"), 64)

	t.Run("MidStreamReadError", func(t *testing.T) {
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		tiered, lower := newTieredWithFailingUpper(t, key, content, len(content)/2)

		r, _, err := tiered.Open(ctx, key)
		assert.NoError(t, err)
		_, err = io.ReadAll(r)
		assert.IsError(t, err, errMidStream)
		assert.NoError(t, r.Close())

		_, _, err = lower.Open(ctx, key)
		assert.IsError(t, err, os.ErrNotExist)
	})

	t.Run("CloseBeforeEOF", func(t *testing.T) {
		_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
		tiered, lower := newTieredWithFailingUpper(t, key, content, len(content))

		r, _, err := tiered.Open(ctx, key)
		assert.NoError(t, err)
		buf := make([]byte, len(content)/2)
		_, err = io.ReadFull(r, buf)
		assert.NoError(t, err)
		assert.NoError(t, r.Close())

		_, _, err = lower.Open(ctx, key)
		assert.IsError(t, err, os.ErrNotExist)
	})
}

// midStreamFailingCache serves failAfter bytes of each opened object and then
// fails the read with err, simulating an upstream stream dying mid-transfer.
type midStreamFailingCache struct {
	cache.Cache
	failAfter int
	err       error
}

func (c midStreamFailingCache) Open(ctx context.Context, key cache.Key, opts ...cache.Option) (io.ReadCloser, http.Header, error) {
	r, h, err := c.Cache.Open(ctx, key, opts...)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck
	}
	return &midStreamFailingReader{r: r, remaining: c.failAfter, err: c.err}, h, nil
}

type midStreamFailingReader struct {
	r         io.ReadCloser
	remaining int
	err       error
}

func (r *midStreamFailingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.err
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= n
	return n, err //nolint:wrapcheck
}

func (r *midStreamFailingReader) Close() error {
	return r.r.Close() //nolint:wrapcheck
}

func TestTieredCreateUsesSameETagInEveryTier(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := newTiered(ctx, lower, upper)
	defer tiered.Close()

	key := cache.NewKey("tiered-create-etag")
	seedTier(ctx, t, tiered, key, []byte("same etag"))

	lowerReader, lowerHeaders, err := lower.Open(ctx, key)
	assert.NoError(t, err)
	assert.NoError(t, lowerReader.Close())
	upperReader, upperHeaders, err := upper.Open(ctx, key)
	assert.NoError(t, err)
	assert.NoError(t, upperReader.Close())
	assert.Equal(t, lowerHeaders.Get(cache.ETagKey), upperHeaders.Get(cache.ETagKey))
}

func TestTieredCreateContinuesWhenMemoryTierDeclinesAdmission(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	constrained, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 8, InflightLimitMB: 2, MaxTTL: time.Hour})
	assert.NoError(t, err)
	authoritative, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 4, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := newTiered(ctx, constrained, authoritative)
	t.Cleanup(func() { assert.NoError(t, tiered.Close()) })
	key := cache.NewKey("declined-memory-admission")
	content := make([]byte, 2*1024*1024)
	content[0] = 1
	headers := http.Header{"Content-Length": {strconv.Itoa(len(content))}}

	writer, err := tiered.Create(ctx, key, headers, time.Hour)
	assert.NoError(t, err)
	written, err := writer.Write(content)
	assert.NoError(t, err)
	assert.Equal(t, len(content), written)
	assert.NoError(t, writer.Close())

	_, _, err = constrained.Open(ctx, key)
	assert.IsError(t, err, os.ErrNotExist)
	reader, _, err := authoritative.Open(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, content, readAllAndClose(t, reader))
}

func TestTieredCreateCancellationAbortsCreatedAndLateWriters(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	ctx, cancel := context.WithCancel(ctx)
	created := make(chan struct{})
	lateCreateStarted := make(chan struct{})
	releaseLateCreate := make(chan struct{})
	firstAborted := make(chan struct{})
	lateAborted := make(chan struct{})
	firstWriter := newRecordingNoOpWriter(t, make(chan struct{}), firstAborted)
	lateWriter := newRecordingNoOpWriter(t, make(chan struct{}), lateAborted)
	first := createFuncCache{
		Cache: cache.NoOpCache(),
		create: func(context.Context, cache.Key, http.Header, time.Duration, ...cache.Option) (cache.Writer, error) {
			close(created)
			return firstWriter, nil
		},
	}
	late := createFuncCache{
		Cache: cache.NoOpCache(),
		create: func(context.Context, cache.Key, http.Header, time.Duration, ...cache.Option) (cache.Writer, error) {
			close(lateCreateStarted)
			<-releaseLateCreate
			return lateWriter, nil
		},
	}
	tiered := newTiered(ctx, first, late)
	result := make(chan error, 1)
	go func() {
		_, err := tiered.Create(ctx, cache.NewKey("cancelled-tiered-create"), nil, time.Hour)
		result <- err
	}()
	<-created
	<-lateCreateStarted
	cancel()
	assert.IsError(t, <-result, context.Canceled)
	select {
	case <-firstAborted:
	case <-time.After(time.Second):
		t.Fatal("created writer was not aborted")
	}
	close(releaseLateCreate)
	select {
	case <-lateAborted:
	case <-time.After(time.Second):
		t.Fatal("late writer was not aborted")
	}
}

func TestTieredCreateErrorAbortsOtherWriters(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	createFailed := errors.New("create failed")
	created := make(chan struct{})
	aborted := make(chan struct{})
	successfulWriter := newRecordingNoOpWriter(t, make(chan struct{}), aborted)
	successful := createFuncCache{
		Cache: cache.NoOpCache(),
		create: func(context.Context, cache.Key, http.Header, time.Duration, ...cache.Option) (cache.Writer, error) {
			close(created)
			return successfulWriter, nil
		},
	}
	failing := createFuncCache{
		Cache: cache.NoOpCache(),
		create: func(context.Context, cache.Key, http.Header, time.Duration, ...cache.Option) (cache.Writer, error) {
			<-created
			return nil, createFailed
		},
	}
	tiered := newTiered(ctx, successful, failing)
	writer, err := tiered.Create(ctx, cache.NewKey("failed-tiered-create"), nil, time.Hour)
	assert.Zero(t, writer)
	assert.IsError(t, err, createFailed)
	select {
	case <-aborted:
	case <-time.After(time.Second):
		t.Fatal("successful writer was not aborted")
	}
}

func TestTieredWriterCloseReleasesCreateContext(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	createdContext := make(chan context.Context, 1)
	recording := createFuncCache{
		Cache: cache.NoOpCache(),
		create: func(
			ctx context.Context,
			key cache.Key,
			headers http.Header,
			ttl time.Duration,
			opts ...cache.Option,
		) (cache.Writer, error) {
			createdContext <- ctx
			return cache.NoOpCache().Create(ctx, key, headers, ttl, opts...)
		},
	}
	tiered := newTiered(ctx, recording, cache.NoOpCache())
	t.Cleanup(func() { assert.NoError(t, tiered.Close()) })
	writer, err := tiered.Create(ctx, cache.NewKey("released-create-context"), nil, time.Hour)
	assert.NoError(t, err)
	writerContext := <-createdContext
	assert.Zero(t, context.Cause(writerContext))
	assert.NoError(t, writer.Close())
	assert.IsError(t, context.Cause(writerContext), context.Canceled)
}

func TestTieredRequiresMetadataStore(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)

	assert.Panics(t, func() {
		cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, nil)
	})
}

func TestStatAuthoritativeBypassesLocalTiers(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	local, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	shared, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := newTiered(ctx, local, shared)

	key := cache.NewKey("stat-authoritative")
	w, err := tiered.Create(ctx, key, nil, time.Minute)
	assert.NoError(t, err)
	_, err = w.Write([]byte("content"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	_, err = cache.StatAuthoritative(ctx, tiered, key)
	assert.NoError(t, err)

	// A lost shared object must be reported missing even while a local tier
	// still holds a copy.
	assert.NoError(t, shared.Delete(ctx, key))
	_, err = tiered.Stat(ctx, key)
	assert.NoError(t, err)
	_, err = cache.StatAuthoritative(ctx, tiered, key)
	assert.IsError(t, err, os.ErrNotExist)

	// Single-tier caches fall back to a plain Stat.
	_, err = cache.StatAuthoritative(ctx, local, key)
	assert.NoError(t, err)
}

func TestTieredCreateDoesNotPublishMetadataETagForNewKey(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-create-metadata-etag")
	w, err := tiered.Create(ctx, key, nil, time.Minute, cache.WithETag("metadata-etag"))
	assert.NoError(t, err)
	_, err = w.Write([]byte("content"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	_, ok := tieredETags(store, "").Get(key)
	assert.False(t, ok)
}

func TestTieredCreatePublishesMetadataETagForReplacement(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-replace-metadata-etag")
	seedTier(ctx, t, tiered, key, []byte("old"), "old-etag")

	w, err := tiered.Create(ctx, key, nil, time.Minute, cache.WithETag("new-etag"))
	assert.NoError(t, err)
	_, err = w.Write([]byte("new"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	etag, ok := tieredETags(store, "").Get(key)
	assert.True(t, ok)
	assert.Equal(t, `"new-etag"`, etag)
}

func TestTieredCreateDoesNotPublishMetadataETagForSameETagReplacement(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-same-metadata-etag")
	seedTier(ctx, t, tiered, key, []byte("old"), "same-etag")

	w, err := tiered.Create(ctx, key, nil, time.Minute, cache.WithETag("same-etag"))
	assert.NoError(t, err)
	_, err = w.Write([]byte("new"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	_, ok := tieredETags(store, "").Get(key)
	assert.False(t, ok)
}

func TestTieredAbortDoesNotPublishMetadataETag(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-abort-metadata-etag")
	w, err := tiered.Create(ctx, key, nil, time.Minute, cache.WithETag("aborted-etag"))
	assert.NoError(t, err)
	_, err = w.Write([]byte("partial"))
	assert.NoError(t, err)
	assert.Error(t, w.Abort(errors.New("abort write")))

	_, ok := tieredETags(store, "").Get(key)
	assert.False(t, ok)
}

func TestTieredMetadataInvalidatesStaleLowerOnStat(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-stale-stat")
	seedTier(ctx, t, lower, key, []byte("stale"), "stale-etag")
	seedTier(ctx, t, upper, key, []byte("fresh"), "fresh-etag")
	assert.NoError(t, tieredETags(store, "").Set(key, `"fresh-etag"`))

	headers, err := tiered.Stat(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, `"fresh-etag"`, headers.Get(cache.ETagKey))
	_, _, err = lower.Open(ctx, key)
	assert.IsError(t, err, os.ErrNotExist)
}

func TestTieredMetadataInvalidatesStaleLowerBeforeNotModified(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-stale-not-modified")
	seedTier(ctx, t, lower, key, []byte("stale"), "stale-etag")
	seedTier(ctx, t, upper, key, []byte("fresh"), "fresh-etag")
	assert.NoError(t, tieredETags(store, "").Set(key, `"fresh-etag"`))

	r, headers, err := tiered.Open(ctx, key, cache.IfNoneMatch(`"stale-etag"`))
	assert.NoError(t, err)
	assert.Equal(t, []byte("fresh"), readAllAndClose(t, r))
	assert.Equal(t, `"fresh-etag"`, headers.Get(cache.ETagKey))
	eventually(t, func() bool { return tierHolds(ctx, t, lower, key, []byte("fresh"), `"fresh-etag"`) })
}

func TestTieredMetadataReturnsHardStatErrorBeforeInvalidating(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	statErr := errors.New("stat unavailable")
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{newStatFailingCache(lower, statErr), upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-stale-hard-stat-error")
	seedTier(ctx, t, lower, key, []byte("lower"), "lower-etag")
	seedTier(ctx, t, upper, key, []byte("upper"), "upper-etag")
	assert.NoError(t, tieredETags(store, "").Set(key, `"upper-etag"`))

	_, err = tiered.Stat(ctx, key)
	assert.IsError(t, err, statErr)
	r, headers, err := lower.Open(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, []byte("lower"), readAllAndClose(t, r))
	assert.Equal(t, `"lower-etag"`, headers.Get(cache.ETagKey))
}

func TestTieredMetadataClearsDiscardedConditionalError(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-clears-stale-conditional")
	seedTier(ctx, t, lower, key, []byte("stale"), "stale-etag")
	assert.NoError(t, tieredETags(store, "").Set(key, `"fresh-etag"`))

	_, _, err = tiered.Open(ctx, key, cache.IfNoneMatch(`"stale-etag"`))
	assert.IsError(t, err, os.ErrNotExist)
	assert.False(t, errors.Is(err, cache.ErrNotModified))
}

func TestTieredMetadataAllowsMatchingLower(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-matching-lower")
	seedTier(ctx, t, lower, key, []byte("lower"), "lower-etag")
	seedTier(ctx, t, upper, key, []byte("upper"), "upper-etag")
	assert.NoError(t, tieredETags(store, "").Set(key, `"lower-etag"`))

	r, headers, err := tiered.Open(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, []byte("lower"), readAllAndClose(t, r))
	assert.Equal(t, `"lower-etag"`, headers.Get(cache.ETagKey))
}

func TestTieredMissingMetadataPreservesExistingBehavior(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-missing-metadata")
	seedTier(ctx, t, lower, key, []byte("lower"), "lower-etag")
	seedTier(ctx, t, upper, key, []byte("upper"), "upper-etag")

	r, headers, err := tiered.Open(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, []byte("lower"), readAllAndClose(t, r))
	assert.Equal(t, `"lower-etag"`, headers.Get(cache.ETagKey))
}

func TestTieredMetadataIsNamespaced(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("tiered-namespaced-metadata")
	namespaced := tiered.Namespace("alpha")
	w, err := namespaced.Create(ctx, key, nil, time.Minute, cache.WithETag("old-alpha-etag"))
	assert.NoError(t, err)
	_, err = w.Write([]byte("old"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	w, err = namespaced.Create(ctx, key, nil, time.Minute, cache.WithETag("alpha-etag"))
	assert.NoError(t, err)
	_, err = w.Write([]byte("new"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	etag, ok := tieredETags(store, "alpha").Get(key)
	assert.True(t, ok)
	assert.Equal(t, `"alpha-etag"`, etag)
	_, ok = tieredETags(store, "beta").Get(key)
	assert.False(t, ok)
}

func TestTieredDivergentValidatorPermutations(t *testing.T) {
	stale := []byte("0123456789")
	pinned := []byte("abcdefghij")
	const staleETag = `"stale-etag"`
	const pinnedETag = `"pinned-etag"`

	for _, perm := range tieredPermutations(t) {
		t.Run(perm.name, func(t *testing.T) {
			_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
			lower := perm.lower.new(t)
			upper := perm.upper.new(t)
			tiered := newTiered(ctx, lower, upper)
			defer tiered.Close()

			keyBoth := cache.NewKey("divergent-both")
			seedTier(ctx, t, lower, keyBoth, stale, "stale-etag")
			seedTier(ctx, t, upper, keyBoth, pinned, "pinned-etag")

			keyLowerOnly := cache.NewKey("divergent-lower-only")
			seedTier(ctx, t, lower, keyLowerOnly, stale, "stale-etag")

			t.Run("IfRangePinnedToUpperServesRangeFromUpper", func(t *testing.T) {
				r, headers, err := tiered.Open(ctx, keyBoth, cache.Range(2, 6), cache.IfRange(pinnedETag))
				assert.NoError(t, err)
				assert.Equal(t, []byte("cdef"), readAllAndClose(t, r))
				assert.Equal(t, "bytes 2-5/10", headers.Get("Content-Range"))
				assert.Equal(t, pinnedETag, headers.Get(cache.ETagKey))
			})

			t.Run("IfRangePinnedToLowerServesRangeFromLower", func(t *testing.T) {
				r, headers, err := tiered.Open(ctx, keyBoth, cache.Range(2, 6), cache.IfRange(staleETag))
				assert.NoError(t, err)
				assert.Equal(t, []byte("2345"), readAllAndClose(t, r))
				assert.Equal(t, staleETag, headers.Get(cache.ETagKey))
			})

			t.Run("IfRangeMissingEverywhereServesFullFromLower", func(t *testing.T) {
				r, headers, err := tiered.Open(ctx, keyBoth, cache.Range(2, 6), cache.IfRange(`"unknown"`))
				assert.NoError(t, err)
				assert.Equal(t, stale, readAllAndClose(t, r))
				assert.Equal(t, "", headers.Get("Content-Range"))
				assert.Equal(t, staleETag, headers.Get(cache.ETagKey))
			})

			t.Run("IfRangePinnedUpperMissingServesFullFromLower", func(t *testing.T) {
				r, headers, err := tiered.Open(ctx, keyLowerOnly, cache.Range(2, 6), cache.IfRange(pinnedETag))
				assert.NoError(t, err)
				assert.Equal(t, stale, readAllAndClose(t, r))
				assert.Equal(t, "", headers.Get("Content-Range"))
			})

			t.Run("IfMatchPinnedToUpperServesRangeFromUpper", func(t *testing.T) {
				r, headers, err := tiered.Open(ctx, keyBoth, cache.Range(2, 6), cache.IfMatch(pinnedETag))
				assert.NoError(t, err)
				assert.Equal(t, []byte("cdef"), readAllAndClose(t, r))
				assert.Equal(t, "bytes 2-5/10", headers.Get("Content-Range"))
				assert.Equal(t, pinnedETag, headers.Get(cache.ETagKey))

				// A partial body must never be backfilled: the lower tier keeps
				// its own version.
				r2, _, err := lower.Open(ctx, keyBoth)
				assert.NoError(t, err)
				assert.Equal(t, stale, readAllAndClose(t, r2))
			})

			t.Run("IfMatchMissingEverywhereReturnsPreconditionFailed", func(t *testing.T) {
				_, _, err := tiered.Open(ctx, keyBoth, cache.Range(2, 6), cache.IfMatch(`"unknown"`))
				assert.IsError(t, err, cache.ErrPreconditionFailed)
				_, err = tiered.Stat(ctx, keyBoth, cache.IfMatch(`"unknown"`))
				assert.IsError(t, err, cache.ErrPreconditionFailed)
			})

			t.Run("IfMatchPinnedUpperMissingReturnsPreconditionFailed", func(t *testing.T) {
				_, _, err := tiered.Open(ctx, keyLowerOnly, cache.Range(2, 6), cache.IfMatch(pinnedETag))
				assert.IsError(t, err, cache.ErrPreconditionFailed)
			})

			t.Run("StatIfMatchPinnedToUpperReturnsUpperHeaders", func(t *testing.T) {
				headers, err := tiered.Stat(ctx, keyBoth, cache.IfMatch(pinnedETag))
				assert.NoError(t, err)
				assert.Equal(t, pinnedETag, headers.Get(cache.ETagKey))
			})

			t.Run("IfNoneMatchLowerRemainsDefinitive", func(t *testing.T) {
				_, _, err := tiered.Open(ctx, keyBoth, cache.IfNoneMatch(staleETag))
				assert.IsError(t, err, cache.ErrNotModified)
			})

			t.Run("IfMatchFullReadBackfillsLower", func(t *testing.T) {
				keyHeal := cache.NewKey("divergent-heal")
				seedTier(ctx, t, lower, keyHeal, stale, "stale-etag")
				seedTier(ctx, t, upper, keyHeal, pinned, "pinned-etag")

				r, headers, err := tiered.Open(ctx, keyHeal, cache.IfMatch(pinnedETag))
				assert.NoError(t, err)
				assert.Equal(t, pinned, readAllAndClose(t, r))
				assert.Equal(t, pinnedETag, headers.Get(cache.ETagKey))

				// A full-body serve from the upper tier heals the divergent
				// lower tier via the usual backfill.
				eventually(t, func() bool { return tierHolds(ctx, t, lower, keyHeal, pinned, pinnedETag) })
			})
		})
	}
}

func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func tierHolds(ctx context.Context, t *testing.T, c cache.Cache, key cache.Key, wantBody []byte, wantETag string) bool {
	t.Helper()
	r, headers, err := c.Open(ctx, key)
	if err != nil {
		return false
	}
	got := readAllAndClose(t, r)
	return string(got) == string(wantBody) && headers.Get(cache.ETagKey) == wantETag
}

func TestTieredRangedReadHealsDivergentTier0(t *testing.T) {
	pinned := []byte("abcdefghij")
	stale := []byte("0123456789")

	for _, validator := range []struct {
		name string
		opts []cache.Option
	}{
		{"IfRange", []cache.Option{cache.Range(2, 6), cache.IfRange(`"pinned-etag"`)}},
		{"IfMatch", []cache.Option{cache.Range(2, 6), cache.IfMatch(`"pinned-etag"`)}},
	} {
		t.Run(validator.name, func(t *testing.T) {
			_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
			store := newMetadataStore(ctx)
			lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
			assert.NoError(t, err)
			upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
			assert.NoError(t, err)
			tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
			defer tiered.Close()

			key := cache.NewKey("heal-ranged")
			seedTier(ctx, t, tiered, key, stale, "stale-etag")
			seedTier(ctx, t, tiered, key, pinned, "pinned-etag")
			seedTier(ctx, t, lower, key, stale, "stale-etag")

			r, headers, err := tiered.Open(ctx, key, validator.opts...)
			assert.NoError(t, err)
			assert.Equal(t, []byte("cdef"), readAllAndClose(t, r))
			assert.Equal(t, `"pinned-etag"`, headers.Get(cache.ETagKey))

			eventually(t, func() bool { return tierHolds(ctx, t, lower, key, pinned, `"pinned-etag"`) })

			assert.NoError(t, upper.Delete(ctx, key))
			r, headers, err = tiered.Open(ctx, key)
			assert.NoError(t, err)
			assert.Equal(t, pinned, readAllAndClose(t, r))
			assert.Equal(t, `"pinned-etag"`, headers.Get(cache.ETagKey))
		})
	}
}

func TestTieredRangedReadKeepsNewerTier0(t *testing.T) {
	newer := []byte("abcdefghij")
	lagging := []byte("0123456789")

	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("heal-newer-tier0")
	seedTier(ctx, t, lower, key, newer, "newer-etag")
	seedTier(ctx, t, upper, key, lagging, "lagging-etag")
	assert.NoError(t, tieredETags(store, "").Set(key, `"newer-etag"`))

	r, headers, err := tiered.Open(ctx, key, cache.Range(2, 6), cache.IfRange(`"lagging-etag"`))
	assert.NoError(t, err)
	assert.Equal(t, []byte("2345"), readAllAndClose(t, r))
	assert.Equal(t, `"lagging-etag"`, headers.Get(cache.ETagKey))

	time.Sleep(100 * time.Millisecond)
	assert.True(t, tierHolds(ctx, t, lower, key, newer, `"newer-etag"`))
}

type gatedCache struct {
	cache.Cache
	opens   atomic.Int32
	gate    chan struct{}
	reached chan struct{}
	once    sync.Once
}

func (c *gatedCache) Open(ctx context.Context, key cache.Key, opts ...cache.Option) (io.ReadCloser, http.Header, error) {
	r, h, err := c.Cache.Open(ctx, key, opts...)
	if err == nil && c.opens.Add(1) == 2 {
		return &gatedReader{ReadCloser: r, gate: c.gate, reached: c.reached, once: &c.once}, h, nil
	}
	return r, h, err
}

type gatedReader struct {
	io.ReadCloser
	gate    chan struct{}
	reached chan struct{}
	once    *sync.Once
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.once.Do(func() {
		close(g.reached)
		<-g.gate
	})
	return g.ReadCloser.Read(p) //nolint:wrapcheck
}

type recordingCache struct {
	cache.Cache
	armed     atomic.Bool
	committed chan struct{}
	aborted   chan struct{}
}

type ttlRecordingCache struct {
	cache.Cache
	ttls chan time.Duration
}

func (c *ttlRecordingCache) Create(
	ctx context.Context,
	key cache.Key,
	headers http.Header,
	ttl time.Duration,
	opts ...cache.Option,
) (cache.Writer, error) {
	c.ttls <- ttl
	return c.Cache.Create(ctx, key, headers, ttl, opts...)
}

func TestTieredPreservesAbsoluteExpirationAcrossBackfill(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lowerMemory, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	lower := &ttlRecordingCache{Cache: lowerMemory, ttls: make(chan time.Duration, 1)}
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("absolute-expiration-backfill")
	expiresAt := time.Now().Add(5 * time.Minute)
	headers := http.Header{cache.ExpirationKey: {expiresAt.UTC().Format(time.RFC3339Nano)}}
	w, err := upper.Create(ctx, key, headers, time.Hour)
	assert.NoError(t, err)
	_, err = w.Write([]byte("payload"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	r, _, err := tiered.Open(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, []byte("payload"), readAllAndClose(t, r))

	backfillTTL := <-lower.ttls
	assert.True(t, backfillTTL > 4*time.Minute+50*time.Second)
	assert.True(t, backfillTTL <= 5*time.Minute)
}

func TestTieredSkipsEntriesPastAbsoluteExpiration(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := newTiered(ctx, lower, upper)
	defer tiered.Close()

	key := cache.NewKey("expired-absolute-expiration")
	headers := http.Header{cache.ExpirationKey: {time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}}
	w, err := upper.Create(ctx, key, headers, time.Hour)
	assert.NoError(t, err)
	_, err = w.Write([]byte("stale"))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	r, _, err := tiered.Open(ctx, key)
	assert.IsError(t, err, os.ErrNotExist)
	assert.Zero(t, r)
}

func (c *recordingCache) Create(ctx context.Context, key cache.Key, headers http.Header, ttl time.Duration, opts ...cache.Option) (cache.Writer, error) {
	w, err := c.Cache.Create(ctx, key, headers, ttl, opts...)
	if err == nil && c.armed.Load() {
		return &recordingWriter{Writer: w, committed: c.committed, aborted: c.aborted}, nil
	}
	return w, err
}

type recordingWriter struct {
	cache.Writer
	committed chan struct{}
	aborted   chan struct{}
	once      sync.Once
}

func (w *recordingWriter) Close() error {
	w.once.Do(func() { close(w.committed) })
	return w.Writer.Close() //nolint:wrapcheck
}

func (w *recordingWriter) Abort(err error) error {
	w.once.Do(func() { close(w.aborted) })
	return w.Writer.Abort(err) //nolint:wrapcheck
}

func TestTieredRangedReadHealAbortsAfterConcurrentDelete(t *testing.T) {
	pinned := []byte("abcdefghij")
	stale := []byte("0123456789")

	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	store := newMetadataStore(ctx)
	lowerMem, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	lower := &recordingCache{Cache: lowerMem, committed: make(chan struct{}), aborted: make(chan struct{})}
	upperMem, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	upper := &gatedCache{Cache: upperMem, gate: make(chan struct{}), reached: make(chan struct{})}
	tiered := cache.MaybeNewTiered(ctx, []cache.Cache{lower, upper}, store)
	defer tiered.Close()

	key := cache.NewKey("heal-delete-race")
	seedTier(ctx, t, tiered, key, stale, "stale-etag")
	seedTier(ctx, t, tiered, key, pinned, "pinned-etag")
	seedTier(ctx, t, lowerMem, key, stale, "stale-etag")
	lower.armed.Store(true)

	r, _, err := tiered.Open(ctx, key, cache.Range(2, 6), cache.IfRange(`"pinned-etag"`))
	assert.NoError(t, err)
	assert.Equal(t, []byte("cdef"), readAllAndClose(t, r))

	select {
	case <-upper.reached:
	case <-time.After(2 * time.Second):
		close(upper.gate)
		t.Fatal("heal did not open source")
	}
	assert.NoError(t, tieredETags(store, "").Delete(key))
	close(upper.gate)

	select {
	case <-lower.aborted:
	case <-lower.committed:
		t.Fatal("heal committed after the etag entry was removed (resurrection)")
	case <-time.After(2 * time.Second):
		t.Fatal("heal did not finish")
	}
}

func TestTieredDivergentValidatorProbeErrors(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	lower, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	outage := errors.New("backend unavailable")
	tiered := newTiered(ctx, lower, newFailingCache(outage))
	defer tiered.Close()

	key := cache.NewKey("divergent-probe-error")
	stale := []byte("0123456789")
	seedTier(ctx, t, lower, key, stale)

	const pinnedETag = `"pinned-etag"`
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "OpenIfMatchReturnsProbeError",
			run: func(t *testing.T) {
				_, _, err := tiered.Open(ctx, key, cache.IfMatch(pinnedETag))
				assert.IsError(t, err, outage)
			},
		},
		{
			name: "StatIfMatchReturnsProbeError",
			run: func(t *testing.T) {
				_, err := tiered.Stat(ctx, key, cache.IfMatch(pinnedETag))
				assert.IsError(t, err, outage)
			},
		},
		{
			name: "OpenIfRangeReturnsProbeError",
			run: func(t *testing.T) {
				_, _, err := tiered.Open(ctx, key, cache.Range(2, 6), cache.IfRange(pinnedETag))
				assert.IsError(t, err, outage)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestTieredDeletePermutations(t *testing.T) {
	for _, perm := range tieredPermutations(t) {
		t.Run(perm.name, func(t *testing.T) {
			_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
			lower := perm.lower.new(t)
			upper := perm.upper.new(t)
			tiered := newTiered(ctx, lower, upper)
			defer tiered.Close()

			key := cache.NewKey("delete-test")
			content := []byte("delete me")

			// Write through tiered so both tiers have the entry.
			seedTier(ctx, t, tiered, key, content)

			// Verify both tiers have it.
			r, _, err := lower.Open(ctx, key)
			assert.NoError(t, err)
			assert.NoError(t, r.Close())
			r, _, err = upper.Open(ctx, key)
			assert.NoError(t, err)
			assert.NoError(t, r.Close())

			// Delete through tiered.
			err = tiered.Delete(ctx, key)
			assert.NoError(t, err)

			// Verify both tiers no longer have it.
			_, _, err = lower.Open(ctx, key)
			assert.IsError(t, err, os.ErrNotExist)
			_, _, err = upper.Open(ctx, key)
			assert.IsError(t, err, os.ErrNotExist)
		})
	}
}

func TestTieredInvalidateSkipsAuthoritativeTier(t *testing.T) {
	for _, perm := range tieredPermutations(t) {
		t.Run(perm.name, func(t *testing.T) {
			_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
			lower := perm.lower.new(t)
			authoritative := perm.upper.new(t)
			tiered := newTiered(ctx, lower, authoritative)
			defer tiered.Close()

			key := cache.NewKey("invalidate-test")
			content := []byte("keep authoritative")
			seedTier(ctx, t, tiered, key, content)

			assert.NoError(t, tiered.Invalidate(ctx, key))
			assert.NoError(t, tiered.Invalidate(ctx, cache.NewKey("missing-invalidate-test")))

			_, _, err := lower.Open(ctx, key)
			assert.IsError(t, err, os.ErrNotExist)

			r, _, err := authoritative.Open(ctx, key)
			assert.NoError(t, err)
			assert.Equal(t, content, readAllAndClose(t, r))
		})
	}
}

func TestSingleTierInvalidateIsNoop(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	authoritative, err := cache.NewMemory(ctx, cache.MemoryConfig{LimitMB: 1024, MaxTTL: time.Hour})
	assert.NoError(t, err)
	tiered := newTiered(ctx, authoritative)
	defer tiered.Close()

	key := cache.NewKey("single-tier-invalidate")
	content := []byte("single authoritative")
	seedTier(ctx, t, tiered, key, content)

	assert.NoError(t, tiered.Invalidate(ctx, key))

	r, _, err := authoritative.Open(ctx, key)
	assert.NoError(t, err)
	assert.Equal(t, content, readAllAndClose(t, r))
}

func TestSingleTierDelegatesUnsupportedOperations(t *testing.T) {
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelDebug})
	tiered := newTiered(ctx, cache.NoOpCache())
	defer tiered.Close()

	_, err := tiered.Stats(ctx)
	assert.IsError(t, err, cache.ErrStatsUnavailable)

	namespaces, err := tiered.ListNamespaces(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{}, namespaces)
}

func TestTieredCacheSoak(t *testing.T) {
	if os.Getenv("SOAK_TEST") == "" {
		t.Skip("Skipping soak test; set SOAK_TEST=1 to run")
	}

	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	memory, err := cache.NewMemory(ctx, cache.MemoryConfig{
		LimitMB: 25,
		MaxTTL:  10 * time.Minute,
	})
	assert.NoError(t, err)
	disk, err := cache.NewDisk(ctx, cache.DiskConfig{
		Root:          t.TempDir(),
		LimitMB:       50,
		MaxTTL:        10 * time.Minute,
		EvictInterval: time.Second,
	})
	assert.NoError(t, err)
	c := newTiered(ctx, memory, disk)
	defer c.Close()

	cachetest.Soak(t, c, cachetest.SoakConfig{
		Duration:         time.Minute,
		NumObjects:       500,
		MaxObjectSize:    512 * 1024,
		MinObjectSize:    1024,
		OverwritePercent: 30,
		Concurrency:      8,
		TTL:              5 * time.Minute,
	})
}
