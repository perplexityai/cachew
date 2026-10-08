package metadatadb_test

import (
	"sync"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/metadatadb/metadatadbtest"
)

func TestMemoryBackend(t *testing.T) {
	metadatadbtest.Suite(t, func(t *testing.T, n int) []metadatadb.Backend {
		t.Helper()
		backend := metadatadb.NewMemoryBackend()
		backends := make([]metadatadb.Backend, n)
		for i := range backends {
			backends[i] = backend
		}
		return backends
	})
}

func TestMemoryBackendConcurrentFirstRead(t *testing.T) {
	backend := metadatadb.NewMemoryBackend()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			<-start
			var result struct {
				Value string
				OK    bool
			}
			err := backend.Query(t.Context(), "new-namespace", metadatadb.MapGet{Key: "entries", MapKey: "missing"}, &result)
			assert.NoError(t, err)
			assert.False(t, result.OK)
		})
	}
	close(start)
	wg.Wait()
}
