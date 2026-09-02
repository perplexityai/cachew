package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	memoryReadinessNamespace  = Namespace("\x00cachew-readiness")
	memoryReadinessInterval   = time.Second
	memoryReadinessStaleAfter = 5 * time.Second
)

type memoryReadiness struct {
	cache       *Memory
	keys        [memoryShardCount]Key
	lastSuccess [memoryShardCount]atomic.Int64
	ctx         context.Context
	cancel      context.CancelFunc
}

func newMemoryReadiness(ctx context.Context, memory *Memory) *memoryReadiness {
	probeCtx, cancel := context.WithCancel(ctx)
	readiness := &memoryReadiness{
		cache:  memoryReadinessView(memory),
		keys:   memoryReadinessKeys(),
		ctx:    probeCtx,
		cancel: cancel,
	}
	for shardIndex, key := range readiness.keys {
		shard := &memory.state.shards[shardIndex]
		entry := &memoryEntry{
			namespace: memoryReadinessNamespace,
			key:       key,
			data:      memoryReadinessPayload(shardIndex),
			expiresAt: time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
			headers: http.Header{
				ETagKey:         {fmt.Sprintf(`"cachew-readiness-%d"`, shardIndex)},
				"Last-Modified": {time.Unix(0, 0).UTC().Format(http.TimeFormat)},
			},
			readiness: true,
		}
		shard.entries[memoryReadinessNamespace] = map[Key]*memoryEntry{key: entry}
		go readiness.run(shardIndex)
	}
	return readiness
}

func memoryReadinessView(memory *Memory) *Memory {
	view := *memory
	view.namespace = memoryReadinessNamespace
	return &view
}

func memoryReadinessKeys() [memoryShardCount]Key {
	var keys [memoryShardCount]Key
	var found [memoryShardCount]bool
	remaining := memoryShardCount
	for candidate := 0; remaining > 0; candidate++ {
		key := NewKey(fmt.Sprintf("cachew-readiness-%d", candidate))
		shardIndex := memoryShardIndex(memoryReadinessNamespace, key)
		if found[shardIndex] {
			continue
		}
		keys[shardIndex] = key
		found[shardIndex] = true
		remaining--
	}
	return keys
}

func memoryReadinessPayload(shardIndex int) []byte {
	return fmt.Appendf(nil, "cachew-readiness-%d", shardIndex)
}

func (r *memoryReadiness) run(shardIndex int) {
	r.probe(shardIndex)
	ticker := time.NewTicker(memoryReadinessInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.probe(shardIndex)
		}
	}
}

func (r *memoryReadiness) probe(shardIndex int) {
	reader, _, err := r.cache.Open(r.ctx, r.keys[shardIndex])
	if err != nil {
		return
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(body, memoryReadinessPayload(shardIndex)) {
		return
	}
	r.lastSuccess[shardIndex].Store(time.Now().UnixNano())
}

func (r *memoryReadiness) ready() bool {
	cutoff := time.Now().Add(-memoryReadinessStaleAfter).UnixNano()
	for index := range r.lastSuccess {
		if r.lastSuccess[index].Load() < cutoff {
			return false
		}
	}
	return true
}

func (r *memoryReadiness) stop() {
	r.cancel()
}

// Ready reports whether every shard has recently served its private sentinel.
func (m *Memory) Ready() bool {
	return m.state.readiness == nil || (!m.state.closed.Load() && m.state.readiness.ready())
}
