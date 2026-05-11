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
// # Tamper-evident chain
//
// The memory store maintains the same per-tenant chain semantics as
// the Postgres store, mostly so unit tests can exercise the
// VerifyChain logic without standing up a database. Storage shape:
// each ring entry carries its own prev_hash + hash + sequence id;
// per-tenant head hashes live in chainHeads. The mutex serializes
// inserts so the chain doesn't fork.
//
// Safe for concurrent use.
type MemoryStore struct {
	mu     sync.RWMutex
	buf    []memoryEntry
	cap    int
	next   int
	filled int

	chainHeads map[string]string // tenant → head hash
	nextID     int64
}

// memoryEntry pairs an event with its chain metadata. The Postgres
// store keeps these as columns; in memory we just embed them.
type memoryEntry struct {
	id       int64
	event    audit.Event
	prevHash string // empty for first event in a tenant's chain
	hash     string // empty for pre-chain rows (none in memory store; here for parity)
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
		buf:        make([]memoryEntry, capacity),
		cap:        capacity,
		chainHeads: map[string]string{},
	}
}

// Insert appends e to the ring + advances the per-tenant chain. O(1).
//
// Hash is SHA-256(prev_hash || canonical_event_json) — same algorithm
// as the Postgres store, so tests written against MemoryStore exercise
// the same VerifyChain logic that ships in production.
func (s *MemoryStore) Insert(_ context.Context, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	chainTenant := e.Tenant
	if chainTenant == "" {
		chainTenant = "default"
	}
	prev := s.chainHeads[chainTenant]

	canon, err := audit.CanonicalForHash(e)
	if err != nil {
		return err
	}
	newHash := audit.ComputeHash(prev, canon)

	s.nextID++
	s.buf[s.next] = memoryEntry{
		id:       s.nextID,
		event:    e,
		prevHash: prev,
		hash:     newHash,
	}
	s.next = (s.next + 1) % s.cap
	if s.filled < s.cap {
		s.filled++
	}
	s.chainHeads[chainTenant] = newHash
	return nil
}

// Query returns events matching the filter, most-recent first. The
// in-memory store is small enough that a linear scan is fine.
func (s *MemoryStore) Query(_ context.Context, f QueryFilter) ([]audit.Event, error) {
	s.mu.RLock()
	all := s.snapshotEntries()
	s.mu.RUnlock()

	matches := make([]audit.Event, 0, len(all))
	for _, entry := range all {
		if !matchesFilter(entry.event, f) {
			continue
		}
		matches = append(matches, entry.event)
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
	all := s.snapshotEntries()
	var n int64
	for _, entry := range all {
		if matchesFilter(entry.event, f) {
			n++
		}
	}
	return n, nil
}

// VerifyChain walks the per-tenant chain in insertion (id) order over
// the optional [from, to] window. Mirrors the Postgres VerifyChain
// shape so unit tests cover the same code path that ships in
// production.
func (s *MemoryStore) VerifyChain(_ context.Context, f VerifyFilter) (VerifyResult, error) {
	tenant := f.Tenant
	if tenant == "" {
		tenant = "default"
	}

	s.mu.RLock()
	entries := s.snapshotEntries()
	s.mu.RUnlock()

	// Sort by insertion id (== monotonic increment in Insert).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].id < entries[j].id
	})

	out := VerifyResult{OK: true}
	var prevHashLink string

	for _, entry := range entries {
		evTenant := entry.event.Tenant
		if evTenant == "" {
			evTenant = "default"
		}
		if evTenant != tenant {
			continue
		}
		if !f.From.IsZero() || !f.To.IsZero() {
			ts, err := time.Parse(time.RFC3339Nano, entry.event.Timestamp)
			if err != nil {
				continue
			}
			if !f.From.IsZero() && ts.Before(f.From) {
				continue
			}
			if !f.To.IsZero() && ts.After(f.To) {
				continue
			}
		}

		if entry.hash == "" {
			out.Skipped++
			continue
		}

		// Chain-link check.
		if out.Verified > 0 && entry.prevHash != prevHashLink {
			out.OK = false
			ts, _ := time.Parse(time.RFC3339Nano, entry.event.Timestamp)
			out.BrokenAt = &VerifyBreak{
				ID:           entry.id,
				Timestamp:    ts,
				StoredHash:   entry.hash,
				ExpectedHash: prevHashLink,
				Reason:       "prev_hash mismatch (chain link broken — row inserted/deleted)",
			}
			return out, nil
		}

		canon, err := audit.CanonicalForHash(entry.event)
		if err != nil {
			return VerifyResult{}, err
		}
		recomputed := audit.ComputeHash(entry.prevHash, canon)
		if recomputed != entry.hash {
			out.OK = false
			ts, _ := time.Parse(time.RFC3339Nano, entry.event.Timestamp)
			out.BrokenAt = &VerifyBreak{
				ID:           entry.id,
				Timestamp:    ts,
				StoredHash:   entry.hash,
				ExpectedHash: recomputed,
				Reason:       "hash mismatch (row body tampered)",
			}
			return out, nil
		}

		out.Verified++
		prevHashLink = entry.hash
	}
	return out, nil
}

// Close is a no-op for the memory store but satisfies the Store
// contract.
func (s *MemoryStore) Close() error { return nil }

// snapshotEntries returns the live entries (event + chain metadata),
// in insertion order. Caller must hold the lock for the duration of
// use.
func (s *MemoryStore) snapshotEntries() []memoryEntry {
	out := make([]memoryEntry, 0, s.filled)
	if s.filled < s.cap {
		out = append(out, s.buf[:s.filled]...)
		return out
	}
	for i := 0; i < s.cap; i++ {
		out = append(out, s.buf[(s.next+i)%s.cap])
	}
	return out
}

// tamperHashAt corrupts the stored hash of the entry at index i.
// Test-only helper exported via the _test.go file in this package.
func (s *MemoryStore) tamperHashAt(i int, newHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf[i].hash = newHash
}

// tamperEventAt mutates the event body at index i without updating
// the stored hash. Test-only helper.
func (s *MemoryStore) tamperEventAt(i int, mutate func(*audit.Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mutate(&s.buf[i].event)
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
	if f.Tenant != "" && e.Tenant != f.Tenant {
		return false
	}
	return true
}
