package auditstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// MemoryStore keeps audit events in a process-local bounded ring
// buffer. Events are lost on gateway restart; not shared across
// replicas.
//
// Bounded so a long-running dev process doesn't grow without limit.
// The default capacity (10_000) keeps a few minutes of typical agent
// traffic — enough for tests and "kicking the tires" but not enough
// for a real audit trail. Production deployments should configure
// [PostgresStore] instead.
//
// Safe for concurrent use.
type MemoryStore struct {
	mu     sync.RWMutex
	buf    []audit.Event
	cap    int
	next   int
	filled int
}

// DefaultMemoryCapacity is the ring-buffer size used when Capacity is
// zero in [NewMemoryStore].
const DefaultMemoryCapacity = 10_000

// NewMemoryStore returns an empty in-memory store. capacity <= 0 falls
// back to DefaultMemoryCapacity.
func NewMemoryStore(capacity int) *MemoryStore {
	if capacity <= 0 {
		capacity = DefaultMemoryCapacity
	}
	return &MemoryStore{
		buf: make([]audit.Event, capacity),
		cap: capacity,
	}
}

// Insert appends e to the ring. O(1).
func (s *MemoryStore) Insert(_ context.Context, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf[s.next] = e
	s.next = (s.next + 1) % s.cap
	if s.filled < s.cap {
		s.filled++
	}
	return nil
}

// Query returns events matching the filter, most-recent first. The
// in-memory store is small enough that a linear scan is fine.
func (s *MemoryStore) Query(_ context.Context, f QueryFilter) ([]audit.Event, error) {
	s.mu.RLock()
	all := s.snapshot()
	s.mu.RUnlock()

	matches := make([]audit.Event, 0, len(all))
	for _, e := range all {
		if !matchesFilter(e, f) {
			continue
		}
		matches = append(matches, e)
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Timestamp > matches[j].Timestamp
	})

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(matches) {
		return []audit.Event{}, nil
	}
	end := offset + limit
	if end > len(matches) {
		end = len(matches)
	}
	return matches[offset:end], nil
}

// Count walks the buffer once. O(n) but the buffer is bounded.
func (s *MemoryStore) Count(_ context.Context, f QueryFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.snapshot()
	var n int64
	for _, e := range all {
		if matchesFilter(e, f) {
			n++
		}
	}
	return n, nil
}

// Close is a no-op for the memory store but satisfies the Store
// contract.
func (s *MemoryStore) Close() error { return nil }

// snapshot returns the live events, in insertion order. Caller must
// hold the lock for the duration of use.
func (s *MemoryStore) snapshot() []audit.Event {
	out := make([]audit.Event, 0, s.filled)
	if s.filled < s.cap {
		out = append(out, s.buf[:s.filled]...)
		return out
	}
	// Ring is full: oldest is at next, walk forward.
	for i := 0; i < s.cap; i++ {
		out = append(out, s.buf[(s.next+i)%s.cap])
	}
	return out
}

// matchesFilter returns true if the event satisfies every non-zero
// field of the filter. Used by both MemoryStore and the test suite.
//
// Timestamp comparison parses the event's RFC3339Nano string so we
// don't rely on lexical ordering — RFC3339Nano omits trailing zeros
// from fractional seconds, which breaks string compare across events
// emitted with different nano precisions.
func matchesFilter(e audit.Event, f QueryFilter) bool {
	if !f.From.IsZero() || !f.To.IsZero() {
		ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			// Unparseable timestamp can't satisfy a window filter.
			return false
		}
		if !f.From.IsZero() && ts.Before(f.From) {
			return false
		}
		if !f.To.IsZero() && ts.After(f.To) {
			return false
		}
	}
	if f.AgentID != "" && e.AgentID != f.AgentID {
		return false
	}
	if f.Tool != "" && e.Tool != f.Tool {
		return false
	}
	if f.Decision != "" && string(e.Decision) != f.Decision {
		return false
	}
	if f.Check != "" && string(e.Check) != f.Check {
		return false
	}
	if f.CapabilityTokenID != "" && e.CapabilityTokenID != f.CapabilityTokenID {
		return false
	}
	return true
}
