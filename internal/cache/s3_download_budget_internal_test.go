package cache

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
	"github.com/minio/minio-go/v7"

	"github.com/block/cachew/internal/logging"
)

const downloadBudgetETag = `"budget-v1"`

type downloadRequests struct {
	mu           sync.Mutex
	counts       map[string]int
	unpinned     int
	rewriteOnGet atomic.Bool
}

func (r *downloadRequests) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[path]
}

func newBudgetTestS3(t *testing.T, config S3Config, data []byte) (*S3, *downloadRequests) {
	t.Helper()
	requests := &downloadRequests{counts: make(map[string]int)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".meta") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		if r.Method == http.MethodGet {
			requests.mu.Lock()
			requests.counts[r.URL.Path]++
			if r.Header.Get("If-Match") != downloadBudgetETag {
				requests.unpinned++
			}
			requests.mu.Unlock()
		}
		w.Header().Set("ETag", downloadBudgetETag)
		if r.Method == http.MethodGet && requests.rewriteOnGet.Load() {
			w.Header().Set("ETag", `"replacement-v2"`)
		}
		w.Header().Set("X-Amz-Meta-Headers", `{"Etag":["\"budget-v1\""]}`)
		http.ServeContent(w, r, "object", time.Unix(1, 0), bytes.NewReader(data))
	}))
	t.Cleanup(server.Close)
	sdk, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{Region: "us-east-1"})
	assert.NoError(t, err)
	config.Bucket = "budget-test"
	config.UploadPartSizeMB = 5
	_, ctx := logging.Configure(t.Context(), logging.Config{})
	s, err := NewS3(ctx, config, func() (*minio.Client, error) { return sdk, nil })
	assert.NoError(t, err)
	return s, requests
}

func TestS3DownloadBudgetSharesAcrossNamespaces(t *testing.T) {
	for _, tc := range []struct {
		name          string
		config        S3Config
		size          int
		opts          []Option
		start, length int
		chunks        int
	}{
		{name: "full", config: S3Config{DownloadConcurrency: 2, DownloadPartSizeMB: 1, DownloadBufferLimitMB: 4}, size: 10 << 20, length: 10 << 20, chunks: 10},
		{name: "range", config: S3Config{DownloadConcurrency: 8, DownloadPartSizeMB: 32, DownloadBufferLimitMB: 16}, size: 24 << 20, opts: []Option{Range(1<<20, 17<<20)}, start: 1 << 20, length: 16 << 20, chunks: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.size)
			_, err := rand.New(rand.NewSource(7)).Read(data)
			assert.NoError(t, err)
			s, requests := newBudgetTestS3(t, tc.config, data)
			slowCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			slow, _, err := s.Open(slowCtx, NewKey("slow"), tc.opts...)
			assert.NoError(t, err)
			defer slow.Close()
			_, err = io.ReadFull(slow, make([]byte, 1))
			assert.NoError(t, err)

			view := s.Namespace("another")
			key := NewKey("fallback")
			fallback, _, err := view.Open(t.Context(), key, tc.opts...)
			assert.NoError(t, err)
			got, err := io.ReadAll(fallback)
			assert.NoError(t, err)
			assert.NoError(t, fallback.Close())
			assert.True(t, bytes.Equal(data[tc.start:tc.start+tc.length], got))
			assert.Equal(t, 1, requests.count("/budget-test/"+s.keyToPath("another", key)), "an exhausted namespace must stream directly")

			cancel()
			assert.NoError(t, slow.Close())
			assert.NoError(t, slow.Close())
			key = NewKey("resumed")
			resumed, _, err := view.Open(t.Context(), key, tc.opts...)
			assert.NoError(t, err)
			got, err = io.ReadAll(resumed)
			assert.NoError(t, err)
			assert.NoError(t, resumed.Close())
			assert.True(t, bytes.Equal(data[tc.start:tc.start+tc.length], got))
			assert.Equal(t, tc.chunks, requests.count("/budget-test/"+s.keyToPath("another", key)), "closing a stalled reader must restore the configured download capacity exactly once")
			requests.mu.Lock()
			unpinned := requests.unpinned
			requests.mu.Unlock()
			assert.Equal(t, 0, unpinned)
		})
	}
}

func TestS3DownloadLargerThanBudgetStreams(t *testing.T) {
	data := bytes.Repeat([]byte("payload"), 2<<20)
	for _, tc := range []struct {
		name          string
		config        S3Config
		opts          []Option
		start, length int
	}{
		{name: "full", config: S3Config{DownloadConcurrency: 2, DownloadPartSizeMB: 1, DownloadBufferLimitMB: 1}, length: len(data)},
		{name: "range_page_rounding", config: S3Config{DownloadConcurrency: 8, DownloadPartSizeMB: 32, DownloadBufferLimitMB: 10}, opts: []Option{Range(1<<20, 10<<20)}, start: 1 << 20, length: 9 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, requests := newBudgetTestS3(t, tc.config, data)
			key := NewKey("oversized-window")
			r, _, err := s.Open(t.Context(), key, tc.opts...)
			assert.NoError(t, err)
			defer r.Close()
			got, err := io.ReadAll(r)
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(data[tc.start:tc.start+tc.length], got))
			assert.Equal(t, 1, requests.count("/budget-test/"+s.keyToPath("", key)))
		})
	}
}

func TestS3DownloadPreservesPreconditions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config S3Config
	}{
		{name: "parallel", config: S3Config{DownloadConcurrency: 2, DownloadPartSizeMB: 1, DownloadBufferLimitMB: 4}},
		{name: "budget_fallback", config: S3Config{DownloadConcurrency: 2, DownloadPartSizeMB: 1, DownloadBufferLimitMB: 1}},
		{name: "small_object", config: S3Config{DownloadConcurrency: 2, DownloadPartSizeMB: 32, DownloadBufferLimitMB: 4}},
		{name: "single_worker", config: S3Config{DownloadConcurrency: 1, DownloadPartSizeMB: 1, DownloadBufferLimitMB: 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, requests := newBudgetTestS3(t, tc.config, bytes.Repeat([]byte("payload"), 1<<20))
			requests.rewriteOnGet.Store(true)
			r, _, err := s.Open(t.Context(), NewKey("changed-after-stat"))
			assert.NoError(t, err)
			defer r.Close()
			got, err := io.ReadAll(r)
			assert.Error(t, err)
			assert.Equal(t, 0, len(got))
			var response minio.ErrorResponse
			assert.True(t, errors.As(err, &response))
			assert.Equal(t, http.StatusPreconditionFailed, response.StatusCode)
		})
	}
}
