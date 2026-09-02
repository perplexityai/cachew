package cache

import (
	"context"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/metadatadb"
)

// The Tiered cache combines multiple caches.
//
// It is not directly selectable from configuration, but instead is automatically used if multiple caches are
// configured.
type Tiered struct {
	caches    []Cache
	metadata  *metadatadb.Store
	etags     *metadatadb.Map[Key, string]
	namespace Namespace
	backfills *tieredBackfills
}

// MaybeNewTiered creates a [Tiered] cache from one or more caches.
//
// If no caches are passed it will panic.
func MaybeNewTiered(ctx context.Context, caches []Cache, metadata *metadatadb.Store) Cache {
	logging.FromContext(ctx).InfoContext(ctx, "Constructing tiered cache", "tiers", len(caches))
	if len(caches) == 0 {
		panic("Tiered cache requires at least one backing cache")
	}
	if len(caches) == 1 {
		return authoritativeCache{Cache: caches[0]}
	}
	if metadata == nil {
		panic("Tiered cache requires a metadata store")
	}
	return Tiered{
		caches:    caches,
		metadata:  metadata,
		etags:     tieredETags(metadata, ""),
		backfills: newTieredBackfills(ctx),
	}
}

type authoritativeCache struct {
	Cache
}

func (c authoritativeCache) Invalidate(context.Context, Key) error {
	return nil
}

func (c authoritativeCache) Namespace(namespace Namespace) Cache {
	return authoritativeCache{Cache: c.Cache.Namespace(namespace)}
}

func (c authoritativeCache) Ready() bool {
	readier, ok := c.Cache.(Readier)
	return !ok || readier.Ready()
}

func (c authoritativeCache) OpenWithTier(
	ctx context.Context,
	key Key,
	opts ...Option,
) (io.ReadCloser, http.Header, BackendType, error) {
	body, headers, err := c.Cache.Open(ctx, key, opts...)
	return body, headers, cacheBackendType(c.Cache), errors.WithStack(err)
}

var _ Cache = (*Tiered)(nil)
var _ Readier = (*Tiered)(nil)

// Close all underlying caches.
func (t Tiered) Close() error {
	// Drain opportunistic work before closing the caches it operates on.
	if t.backfills != nil {
		t.backfills.close()
	}
	wg := sync.WaitGroup{}
	errs := make([]error, len(t.caches))
	for i, cache := range t.caches {
		wg.Go(func() { errs[i] = errors.WithStack(cache.Close()) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Create a new object. All underlying caches will be written to in sequence.
func (t Tiered) Create(ctx context.Context, key Key, headers http.Header, ttl time.Duration, opts ...Option) (Writer, error) {
	rawETag, quotedETag, err := createETag(opts...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	createOpts := []Option{WithETag(rawETag)}

	replaceETag, err := t.replacementETag(ctx, key, quotedETag)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(ctx)

	tw := &tieredWriter{
		writers:     make([]Writer, len(t.caches)),
		cancel:      cancel,
		etags:       t.etags,
		key:         key,
		etag:        quotedETag,
		replaceETag: replaceETag,
	}
	type createResult struct {
		index  int
		writer Writer
		err    error
	}
	// An unbuffered result forces a writer that finishes after cancellation to
	// take the context branch and abort itself instead of becoming orphaned.
	results := make(chan createResult)
	for i, cache := range t.caches {
		go func() {
			w, err := cache.Create(ctx, key, headers, ttl, createOpts...)
			result := createResult{index: i, writer: w, err: err}
			select {
			case results <- result:
			case <-ctx.Done():
				if w != nil {
					_ = w.Abort(context.Cause(ctx)) //nolint:errcheck // The caller has already returned; abort still releases local resources.
				}
			}
		}()
	}
	for range t.caches {
		select {
		case result := <-results:
			tw.writers[result.index] = result.writer
			if result.err != nil {
				cancel(result.err)
				return nil, errors.Join(errors.WithStack(result.err), abortTieredWriters(tw.writers, result.err))
			}
			if result.writer == nil {
				err := errors.New("cache returned a nil writer")
				cancel(err)
				return nil, errors.Join(err, abortTieredWriters(tw.writers, err))
			}
		case <-ctx.Done():
			cause := context.Cause(ctx)
			return nil, errors.Join(errors.WithStack(cause), abortTieredWriters(tw.writers, cause))
		}
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, errors.Join(errors.WithStack(cause), abortTieredWriters(tw.writers, cause))
	}
	return tw, nil
}

func abortTieredWriters(writers []Writer, cause error) error {
	wg := sync.WaitGroup{}
	errs := make([]error, len(writers))
	for i, writer := range writers {
		if writer == nil {
			continue
		}
		wg.Go(func() { errs[i] = errors.WithStack(writer.Abort(cause)) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (t Tiered) replacementETag(ctx context.Context, key Key, newETag string) (bool, error) {
	headers, err := t.caches[len(t.caches)-1].Stat(ctx, key)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, errors.WithStack(err)
	default:
		return headers.Get(ETagKey) != newETag, nil
	}
}

// Delete from all underlying caches. All errors are returned.
func (t Tiered) Delete(ctx context.Context, key Key) error {
	wg := sync.WaitGroup{}
	errs := make([]error, len(t.caches))
	for i, cache := range t.caches {
		wg.Go(func() { errs[i] = errors.WithStack(cache.Delete(ctx, key)) })
	}
	wg.Wait()
	err := errors.Join(errs...)
	if err == nil {
		err = errors.Wrap(t.etags.Delete(key), "delete tiered etag")
	}
	return err
}

// Invalidate evicts stale local copies from every non-authoritative tier.
// The final tier is authoritative by construction, so invalidation leaves it
// intact even if that backend's own Invalidate method would remove the object.
func (t Tiered) Invalidate(ctx context.Context, key Key) error {
	if len(t.caches) <= 1 {
		return nil
	}
	wg := sync.WaitGroup{}
	errs := make([]error, len(t.caches)-1)
	for i, cache := range t.caches[:len(t.caches)-1] {
		wg.Go(func() { errs[i] = errors.WithStack(cache.Invalidate(ctx, key)) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Stat returns headers from the first cache that succeeds.
//
// A tier that fails an If-Match precondition holds a different version of the
// object, not a definitive answer: deeper tiers are consulted for the version
// the validator names, and ErrPreconditionFailed is only returned when none
// holds it. A tier that errored while being probed takes precedence, so
// outages are not misreported as missing versions.
//
// If all caches fail, all errors are returned.
func (t Tiered) Stat(ctx context.Context, key Key, opts ...Option) (http.Header, error) {
	rejected := false
	var probeErrs []error
	errs := make([]error, len(t.caches))
	for i, c := range t.caches {
		headers, err := c.Stat(ctx, key, opts...)
		errs[i] = err
		if cacheEntryExpired(headers, time.Now()) {
			errs[i] = os.ErrNotExist
			continue
		}
		switch {
		case errors.Is(err, os.ErrNotExist) || (errors.Is(err, ErrTierUnavailable) && i < len(t.caches)-1):
			continue
		case errors.Is(err, ErrPreconditionFailed):
			rejected = true
			continue
		case err != nil && !errors.Is(err, ErrNotModified) && rejected:
			probeErrs = append(probeErrs, errors.WithStack(err))
			continue
		case err != nil && !errors.Is(err, ErrNotModified):
			return headers, errors.WithStack(err)
		}
		if i < len(t.caches)-1 && t.invalidateStale(ctx, c, key, headers) {
			continue
		}
		// Any other outcome (success, ErrNotModified, or a hard error) is
		// definitive for this tier; surface it with its headers.
		return headers, errors.WithStack(err)
	}
	if len(probeErrs) > 0 {
		return nil, errors.Join(probeErrs...)
	}
	if rejected {
		return nil, errors.WithStack(ErrPreconditionFailed)
	}
	return nil, errors.Join(errs...)
}

// AuthoritativeStater reports object existence in authoritative shared
// storage, bypassing local tiers whose copies can outlive a lost shared
// object.
type AuthoritativeStater interface {
	AuthoritativeStat(ctx context.Context, key Key, opts ...Option) (http.Header, error)
}

var _ AuthoritativeStater = (*Tiered)(nil)

// AuthoritativeStat stats the final tier, which is authoritative by
// construction.
func (t Tiered) AuthoritativeStat(ctx context.Context, key Key, opts ...Option) (http.Header, error) {
	headers, err := t.caches[len(t.caches)-1].Stat(ctx, key, opts...)
	if cacheEntryExpired(headers, time.Now()) {
		return nil, os.ErrNotExist
	}
	return headers, errors.WithStack(err)
}

// StatAuthoritative stats the authoritative tier when the cache is tiered,
// and falls back to a plain Stat for single-tier caches.
func StatAuthoritative(ctx context.Context, c Cache, key Key, opts ...Option) (http.Header, error) {
	if as, ok := c.(AuthoritativeStater); ok {
		headers, err := as.AuthoritativeStat(ctx, key, opts...)
		return headers, errors.WithStack(err)
	}
	headers, err := c.Stat(ctx, key, opts...)
	if cacheEntryExpired(headers, time.Now()) {
		return nil, os.ErrNotExist
	}
	return headers, errors.WithStack(err)
}

// Open returns a reader from the first cache that succeeds.
// When a higher tier hits but lower tiers missed, the returned reader
// opportunistically backfills tier zero as the caller reads. Once the
// asynchronous fill commits, subsequent Opens are served locally.
//
// A tier that holds a different version than the request's validators name —
// a failed If-Match, or an If-Range miss — is not definitive: deeper tiers are
// consulted for the named version, so a replica whose local tier has diverged
// can still satisfy a pinned request from a shared tier. When no tier holds
// it, the first tier's outcome stands: the full representation for an If-Range
// miss (per RFC 9110), ErrPreconditionFailed for a failed If-Match. A tier
// that errored while being probed takes precedence over both, so outages are
// not misreported as missing versions.
//
// If all caches fail, all errors are returned.
func (t Tiered) Open(ctx context.Context, key Key, opts ...Option) (io.ReadCloser, http.Header, error) {
	body, headers, _, err := t.OpenWithTier(ctx, key, opts...)
	return body, headers, err
}

// OpenWithTier reports the source before a tier-zero backfill can obscure which
// backend supplied the representation.
func (t Tiered) OpenWithTier(ctx context.Context, key Key, opts ...Option) (io.ReadCloser, http.Header, BackendType, error) {
	ro := NewRequestOptions(opts...)
	// A Range request yields a partial body, which must never be backfilled
	// into a lower tier as if it were the whole object.
	partial := ro.Range != ""

	// The first tier whose version missed If-Range supplies the full-body
	// fallback, served only if no deeper tier holds the pinned version.
	var fallback io.ReadCloser
	var fallbackHeaders http.Header
	var fallbackTier BackendType
	var probeErrs []error
	rejected := false // a tier failed If-Match; deeper tiers may hold the named version

	errs := make([]error, len(t.caches))
	for i, c := range t.caches {
		r, headers, err := c.Open(ctx, key, opts...)
		r, headers, err = unexpiredCacheResult(r, headers, err, time.Now())
		errs[i] = err
		switch {
		case errors.Is(err, os.ErrNotExist) || (errors.Is(err, ErrTierUnavailable) && i < len(t.caches)-1):
			continue
		case errors.Is(err, ErrPreconditionFailed):
			rejected = true
			continue
		case t.invalidateStaleConditional(ctx, i, c, key, headers, err, errs):
			continue
		case errors.Is(err, ErrNotModified), errors.Is(err, ErrRangeNotSatisfiable):
			// This tier's version satisfies the request's validator, so the
			// outcome is definitive. Surface headers so callers can build the
			// conditional response. No body to backfill.
			if fallback != nil {
				discardTieredReader(ctx, key, fallback)
			}
			return nil, headers, cacheBackendType(c), errors.WithStack(err)
		case err != nil:
			// A hard error is definitive when no earlier tier produced a
			// servable outcome. Otherwise defer it: a deeper tier may still
			// satisfy the validator, but if none does the error is surfaced in
			// preference to the degraded fallback/412.
			if fallback == nil && !rejected {
				return nil, headers, cacheBackendType(c), errors.WithStack(err)
			}
			probeErrs = append(probeErrs, errors.WithStack(err))
			continue
		case i < len(t.caches)-1 && t.invalidateStale(ctx, c, key, headers):
			discardTieredReader(ctx, key, r)
			continue
		case ro.IfRangeMisses(headers.Get(ETagKey)):
			// This tier holds a different version than the range is pinned to:
			// hold its full body as the fallback and probe deeper tiers.
			if fallback != nil {
				discardTieredReader(ctx, key, r)
				continue
			}
			fallback, fallbackHeaders, fallbackTier = r, headers, cacheBackendType(c)
			continue
		}
		if fallback != nil {
			discardTieredReader(ctx, key, fallback)
		}
		return t.convergeTier0(ctx, key, r, headers, c, i, partial), headers, cacheBackendType(c), nil
	}
	if len(probeErrs) > 0 {
		if fallback != nil {
			probeErrs = append(probeErrs, fallback.Close())
		}
		return nil, nil, backendUnknown, errors.Join(probeErrs...)
	}
	if fallback != nil {
		return fallback, fallbackHeaders, fallbackTier, nil
	}
	if rejected {
		return nil, nil, backendUnknown, errors.WithStack(ErrPreconditionFailed)
	}
	return nil, nil, backendUnknown, errors.Join(errs...)
}

func cacheBackendType(c Cache) BackendType {
	if typed, ok := c.(backendTypedCache); ok {
		return typed.backendType()
	}
	return backendUnknown
}

func discardTieredReader(ctx context.Context, key Key, r io.ReadCloser) {
	if err := r.Close(); err != nil {
		logging.FromContext(ctx).WarnContext(ctx, "Tiered: failed to close superseded reader", "key", key, "error", err)
	}
}

// backfillReader wraps src with an optional asynchronous fill. Admission,
// writer creation, writes, and commit never block the caller; saturation or an
// incomplete source stream discards only the fill.
func (t Tiered) backfillReader(ctx context.Context, key Key, src io.ReadCloser, headers http.Header, dst Cache) io.ReadCloser {
	if t.backfills == nil {
		return src
	}
	servedETag := headers.Get(ETagKey)
	rawETag, err := RawETagFromHeader(servedETag)
	if err != nil {
		return src
	}
	lease, ok := t.backfills.start(ctx, tieredBackfillKey{namespace: t.namespace, key: key, etag: servedETag})
	if !ok {
		return src
	}
	backfillHeaders := headers.Clone()
	ttl := cacheEntryTTL(backfillHeaders, time.Now())
	create := func(ctx context.Context) (Writer, error) {
		return dst.Create(ctx, key, backfillHeaders, ttl, WithETag(rawETag))
	}
	return newBackfillReadCloser(src, create, lease)
}

const tieredETagsMap = "cache-etags"

func tieredETags(metadata *metadatadb.Store, namespace Namespace) *metadatadb.Map[Key, string] {
	return metadatadb.NewMap[Key, string](metadata.Namespace(string(namespace)), tieredETagsMap)
}

func (t Tiered) invalidateStale(ctx context.Context, c Cache, key Key, headers http.Header) bool {
	want, ok := t.etags.Get(key)
	if !ok || want == headers.Get(ETagKey) {
		return false
	}
	if err := c.Invalidate(ctx, key); err != nil {
		logging.FromContext(ctx).WarnContext(ctx, "Tiered: failed to invalidate stale tier", "key", key, "error", err)
	}
	return true
}

func (t Tiered) invalidateStaleConditional(
	ctx context.Context,
	tier int,
	c Cache,
	key Key,
	headers http.Header,
	err error,
	errs []error,
) bool {
	if tier == len(t.caches)-1 || (!errors.Is(err, ErrNotModified) && !errors.Is(err, ErrRangeNotSatisfiable)) {
		return false
	}
	if !t.invalidateStale(ctx, c, key, headers) {
		return false
	}
	errs[tier] = os.ErrNotExist
	return true
}

var errHealSuperseded = errors.New("heal superseded by concurrent write")

func (t Tiered) convergeTier0(ctx context.Context, key Key, r io.ReadCloser, headers http.Header, source Cache, tier int, partial bool) io.ReadCloser {
	switch {
	case tier == 0:
		return r
	case !partial:
		return t.backfillReader(ctx, key, r, headers, t.caches[0])
	default:
		// A ranged body can't backfill tier 0, so refresh it out of band;
		// otherwise a divergent tier 0 never converges under ParallelGet.
		t.healTier0(ctx, key, source, headers.Get(ETagKey))
		return r
	}
}

func (t Tiered) healTier0(reqCtx context.Context, key Key, source Cache, servedETag string) {
	if t.backfills == nil || servedETag == "" {
		return
	}
	rawETag, err := RawETagFromHeader(servedETag)
	if err != nil {
		return
	}
	// Skip if tier 0 is legitimately newer than the served version, so a lagging
	// deeper tier never overwrites it.
	want, ok := t.etags.Get(key)
	if !ok || want != servedETag {
		return
	}
	t.backfills.trigger(reqCtx, tieredBackfillKey{namespace: t.namespace, key: key, etag: servedETag}, func(ctx context.Context) {
		t.backfillTier0FromSource(ctx, key, source, want, rawETag)
	})
}

func (t Tiered) backfillTier0FromSource(ctx context.Context, key Key, source Cache, wantETag, rawETag string) {
	logger := logging.FromContext(ctx)
	r, headers, err := source.Open(ctx, key, IfMatch(wantETag))
	if err != nil {
		logger.WarnContext(ctx, "Tiered: ranged heal source read failed", "key", key, "etag", wantETag, "error", err)
		return
	}
	defer discardTieredReader(ctx, key, r)
	if headers.Get(ETagKey) != wantETag {
		return
	}

	ttl := cacheEntryTTL(headers, time.Now())
	w, err := t.caches[0].Create(ctx, key, headers, ttl, WithETag(rawETag))
	if err != nil {
		logger.WarnContext(ctx, "Tiered: ranged heal writer create failed", "key", key, "error", err)
		return
	}
	if _, err := io.Copy(w, r); err != nil {
		logger.WarnContext(ctx, "Tiered: ranged heal copy failed", "key", key, "error", errors.Join(err, w.Abort(err)))
		return
	}
	// A concurrent Delete drops the etag entry; committing then would resurrect an
	// object that invalidateStale can no longer clean up (it only fires on an
	// etag mismatch, not a missing entry). Re-check narrows that window.
	if got, ok := t.etags.Get(key); !ok || got != wantETag {
		if err := w.Abort(errHealSuperseded); err != nil {
			logger.WarnContext(ctx, "Tiered: ranged heal abort failed", "key", key, "error", err)
		}
		return
	}
	if err := w.Close(); err != nil {
		logger.WarnContext(ctx, "Tiered: ranged heal commit failed", "key", key, "error", err)
	}
}

func (t Tiered) String() string {
	names := make([]string, len(t.caches))
	for i, c := range t.caches {
		names[i] = c.String()
	}
	return "tiered:" + strings.Join(names, ",")
}

func (t Tiered) Stats(ctx context.Context) (Stats, error) {
	var combined Stats
	for _, c := range t.caches {
		s, err := c.Stats(ctx)
		if errors.Is(err, ErrStatsUnavailable) {
			continue
		}
		if err != nil {
			return Stats{}, errors.Wrap(err, c.String())
		}
		combined.Objects += s.Objects
		combined.Size += s.Size
		combined.Capacity += s.Capacity
	}
	return combined, nil
}

// Ready reports false when any local tier with a readiness signal is unhealthy.
func (t Tiered) Ready() bool {
	for _, cache := range t.caches {
		if readier, ok := cache.(Readier); ok && !readier.Ready() {
			return false
		}
	}
	return true
}

type tieredWriter struct {
	writers     []Writer
	cancel      context.CancelCauseFunc
	etags       *metadatadb.Map[Key, string]
	key         Key
	etag        string
	replaceETag bool
	closed      bool
	aborted     bool
}

var _ Writer = (*tieredWriter)(nil)

func (t *tieredWriter) Abort(err error) error {
	t.aborted = true
	t.cancel(err)
	return t.Close()
}

// Close all writers and return all errors.
func (t *tieredWriter) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	defer t.cancel(nil)

	wg := sync.WaitGroup{}
	errs := make([]error, len(t.writers))
	for i, cache := range t.writers {
		wg.Go(func() { errs[i] = errors.WithStack(cache.Close()) })
	}
	wg.Wait()
	err := errors.Join(errs...)
	if err == nil && !t.aborted && t.replaceETag {
		err = errors.Wrap(t.etags.Set(t.key, t.etag), "set tiered etag")
	}
	return err
}

func (t *tieredWriter) Write(p []byte) (n int, err error) {
	for _, cache := range t.writers {
		n, err = cache.Write(p)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.cancel(err)
			}
			return n, errors.WithStack(err)
		}
	}
	return
}

// Namespace creates a namespaced view of the tiered cache.
// All underlying caches are also namespaced.
func (t Tiered) Namespace(namespace Namespace) Cache {
	namespaced := make([]Cache, len(t.caches))
	for i, c := range t.caches {
		namespaced[i] = c.Namespace(namespace)
	}
	return Tiered{
		caches:    namespaced,
		metadata:  t.metadata,
		etags:     tieredETags(t.metadata, namespace),
		namespace: namespace,
		backfills: t.backfills,
	}
}

// ListNamespaces returns unique namespaces from all underlying caches.
func (t Tiered) ListNamespaces(ctx context.Context) ([]string, error) {
	namespaceSet := make(map[string]bool)
	for _, c := range t.caches {
		namespaces, err := c.ListNamespaces(ctx)
		if err != nil && !errors.Is(err, ErrStatsUnavailable) {
			return nil, errors.WithStack(err)
		}
		for _, ns := range namespaces {
			namespaceSet[ns] = true
		}
	}

	namespaces := make([]string, 0, len(namespaceSet))
	for ns := range namespaceSet {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}
