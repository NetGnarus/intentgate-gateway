package budget

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryStore is a process-local Store implementation backed by a
// sync.Map of atomic int64 counters with per-key expiry.
//
// Suitable for single-replica deployments and unit tests. NOT safe
// for multi-replica production: each gateway replica has its own
// counters, so a token's effective budget is multiplied by the
// replica count. Use [RedisStore] in those cases.
type MemoryStore struct {
	entries sync.Map // map[string]*memEntry
}

type memEntry struct {
	count   atomic.Int64
	expires int64 // unix nanoseconds; 0 = never expires
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

// Increment satisfies Store.
func (m *MemoryStore) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	now := time.Now().UnixNano()
	expires := int64(0)
	if ttl > 0 {
		expires = now + ttl.Nanoseconds()
	}

	for {
		actual, _ := m.entries.LoadOrStore(key, &memEntry{expires: expires})
		entry := actual.(*memEntry)

		// If the entry has expired, replace it atomically with a fresh
		// one starting at 1. A racing increment that lost the swap
		// just sees the new entry on the next iteration.
		if entry.expires != 0 && now > entry.expires {
			fresh := &memEntry{expires: expires}
			fresh.count.Store(1)
			if m.entries.CompareAndSwap(key, entry, fresh) {
				return 1, nil
			}
			continue
		}
		return entry.count.Add(1), nil
	}
}

// Reset removes all entries. Test-only.
func (m *MemoryStore) Reset() {
	m.entries = sync.Map{}
}
