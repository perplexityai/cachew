package cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/alecthomas/errors"
	"github.com/minio/minio-go/v7"

	"github.com/block/cachew/client"
)

// minRangePartSize is the smallest ranged-read part worth fetching in parallel.
//
// Below this, per-request overhead outweighs the bandwidth gained from additional streams.
const minRangePartSize int64 = 4 << 20

func (s *S3) parallelGetReader(ctx context.Context, bucket, objectName string, size int64, etag string) (io.ReadCloser, error) {
	chunkSize := int64(s.config.DownloadPartSizeMB) << 20                                      // #nosec G115 -- DownloadPartSizeMB is a small operator-supplied tuning value.
	if concurrency := int(s.config.DownloadConcurrency); size > chunkSize && concurrency > 1 { // #nosec G115 -- DownloadConcurrency is a small operator-supplied tuning value.
		window := &s3ObjectWindow{s3: s, bucket: bucket, objectName: objectName, start: 0, length: size, etag: etag}
		return s.bufferedGetReader(ctx, window, chunkSize, concurrency)
	}
	opts := minio.GetObjectOptions{}
	if etag != "" {
		if err := opts.SetMatchETag(etag); err != nil {
			return nil, errors.Errorf("set etag %s: %w", etag, err)
		}
	}
	obj, err := s.client.GetObject(ctx, bucket, objectName, opts)
	if err != nil {
		return nil, errors.Errorf("failed to get object: %w", err)
	}
	return &s3Reader{obj: obj}, nil
}

// rangedGetReader serves [start, start+length) of an S3 object.
//
// Large ranges fan out as parallel sub-ranges because one S3 stream uses a fraction of the bandwidth.
// Parts shrink to a floor of minRangePartSize so ranges under one configured part still fan out.
func (s *S3) rangedGetReader(ctx context.Context, bucket, objectName string, start, length int64, etag string) (io.ReadCloser, error) { //nolint:privatedoc // explains why
	concurrency := int64(s.config.DownloadConcurrency) // #nosec G115 -- DownloadConcurrency is a small operator-supplied tuning value.
	if length < 2*minRangePartSize || concurrency <= 1 {
		return s.rangeGetReader(ctx, bucket, objectName, start, length, etag)
	}
	chunkSize := 1 + (length-1)/concurrency
	chunkSize = min(max(chunkSize, minRangePartSize), int64(s.config.DownloadPartSizeMB)<<20) // #nosec G115 -- DownloadPartSizeMB is a small operator-supplied tuning value.
	window := &s3ObjectWindow{s3: s, bucket: bucket, objectName: objectName, start: start, length: length, etag: etag}
	return s.bufferedGetReader(ctx, window, chunkSize, int(concurrency))
}

func (s *S3) bufferedGetReader(ctx context.Context, window *s3ObjectWindow, chunkSize int64, concurrency int) (io.ReadCloser, error) {
	pages := min(2*int64(concurrency), 1+(window.length-1)/chunkSize)
	if pages > (s.config.DownloadBufferLimitMB<<20)/chunkSize || !s.downloadBuffers.TryAcquire(pages*chunkSize) {
		return s.rangeGetReader(ctx, window.bucket, window.objectName, window.start, window.length, window.etag)
	}
	reader, err := client.ParallelGetReader(ctx, window, Key{}, chunkSize, concurrency)
	if err != nil {
		s.downloadBuffers.Release(pages * chunkSize)
		return nil, errors.WithStack(err)
	}
	return &budgetedDownloadReader{ReadCloser: reader, release: func() { s.downloadBuffers.Release(pages * chunkSize) }}, nil
}

type budgetedDownloadReader struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

func (r *budgetedDownloadReader) Close() error {
	r.once.Do(func() {
		r.err = r.ReadCloser.Close()
		r.release()
	})
	return r.err
}

// rangeGetReader returns a reader for a single byte range of an S3 object.
//
// A non-empty etag pins the read to one object revision.
func (s *S3) rangeGetReader(ctx context.Context, bucket, objectName string, start, length int64, etag string) (io.ReadCloser, error) { //nolint:privatedoc // explains why
	opts := minio.GetObjectOptions{}
	if err := opts.SetRange(start, start+length-1); err != nil {
		return nil, errors.Errorf("set range %d-%d: %w", start, start+length-1, err)
	}
	if etag != "" {
		if err := opts.SetMatchETag(etag); err != nil {
			return nil, errors.Errorf("set etag %s: %w", etag, err)
		}
	}
	obj, err := s.client.GetObject(ctx, bucket, objectName, opts)
	if err != nil {
		return nil, errors.Errorf("failed to get object range: %w", err)
	}
	return &s3Reader{obj: obj}, nil
}

// s3ObjectWindow adapts a byte window of a pinned S3 object revision to [client.RangeReader] for ParallelGet.
//
// Offsets are window-relative and every request carries If-Match for the pinned etag, so requests never splice
// revisions. minio enforces the preconditions, so headers are synthesized from pinned values; Key is ignored.
type s3ObjectWindow struct {
	s3         *S3
	bucket     string
	objectName string
	start      int64 // window offset within the object
	length     int64 // window size in bytes
	etag       string
}

func (w *s3ObjectWindow) Open(ctx context.Context, _ Key, opts ...Option) (io.ReadCloser, http.Header, error) {
	start, length, outcome := NewRequestOptions(opts...).ResolveRange(w.length, w.etag)
	headers := http.Header{}
	if w.etag != "" {
		headers.Set(ETagKey, w.etag)
	}
	switch outcome {
	case RangeNotSatisfiable:
		headers.Set("Content-Range", fmt.Sprintf("bytes */%d", w.length))
		return nil, headers, errors.WithStack(ErrRangeNotSatisfiable)
	case RangePartial:
		headers.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, w.length))
	case RangeFull:
	}
	rc, err := w.s3.rangeGetReader(ctx, w.bucket, w.objectName, w.start+start, length, w.etag)
	if err != nil {
		return nil, nil, err
	}
	return rc, headers, nil
}
