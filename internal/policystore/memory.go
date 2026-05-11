package policystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// MemoryStore keeps drafts and the per-tenant active pointers in
// process-local maps. Single-replica only, lost on restart.
// Production deployments supply [PostgresStore].
//
// Safe for concurrent use; one mutex guards every field. Contention
// is fine: policy authoring is operator-driven (RPS << 1).
type MemoryStore struct {
	mu     sync.RWMutex
	drafts map[string]Draft
	// active is keyed by tenant. The empty-string key is the default-
	// fallback row (the v1.4 "global" semantic). Per-tenant rows are
	// only populated after a per-tenant admin promotes against their
	// tenant slot.
	active map[string]Active
	// watchers is the set of subscribers receiving fan-out
	// notifications from Promote and Rollback. Each Watch call
	// appends; ctx-cancel removes. Bounded buffer per channel so a
	// slow consumer can't backpressure the writer goroutine.
	watchers []chan Active
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		drafts: make(map[string]Draft),
		active: make(map[string]Active),
	}
}

// Close closes any outstanding Watch channels so callers blocked on
// them see a clean exit. Drafts and the active pointer remain
// readable after Close — the store doesn't enforce a state machine
// here; the gateway shuts down the whole process around it.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.watchers {
		close(ch)
	}
	s.watchers = nil
	return nil
}

// Watch subscribes to active-pointer changes. The returned channel
// is buffered (4) so a brief blip in the consumer doesn't drop
// notifications; a sustained backlog drops on send (the consumer
// resyncs via the next change or by re-reading on its own).
//
// The subscription stays alive until ctx is cancelled; a tiny
// goroutine watches ctx.Done and unregisters the channel.
func (s *MemoryStore) Watch(ctx context.Context) (<-chan Active, error) {
	ch := make(chan Active, 4)
	s.mu.Lock()
	s.watchers = append(s.watchers, ch)
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.unsubscribe(ch)
	}()
	return ch, nil
}

// unsubscribe removes a watcher channel from the registry and
// closes it. Idempotent: a no-op if the channel was already
// removed (Close drained everyone).
func (s *MemoryStore) unsubscribe(target chan Active) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ch := range s.watchers {
		if ch == target {
			s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
			close(ch)
			return
		}
	}
}

// notifyWatchers fans out an Active value to every subscribed
// channel, dropping on full buffer (best-effort delivery — the
// consumer's reaction is idempotent so missing one is fine, and
// blocking here would let one slow consumer stall the next
// Promote). Called from within Promote/Rollback under s.mu, so
// watchers being mutated concurrently is impossible during the
// fan-out.
func (s *MemoryStore) notifyWatchers(a Active) {
	for _, ch := range s.watchers {
		select {
		case ch <- a:
		default:
			// Slow consumer; drop. They'll see the next change or
			// can re-read on their own.
		}
	}
}

// newID generates a short random hex ID. Collisions across an
// operator's draft library are essentially zero at 16 hex chars
// (64 bits); we're not minting these by the million.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// CreateDraft inserts a new draft with a generated ID. CreatedAt
// and UpdatedAt are set to the current UTC time; the caller's
// values are ignored (the store owns time-stamping, same shape as
// revocation and approvals stores).
func (s *MemoryStore) CreateDraft(_ context.Context, d Draft) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	d.ID = newID()
	d.CreatedAt = now
	d.UpdatedAt = now
	s.drafts[d.ID] = d
	return d, nil
}

// UpdateDraft replaces fields on an existing row. Tenant on the
// stored row is preserved (callers can't move drafts across
// tenants via update). CreatedAt is preserved; UpdatedAt advances
// to now.
func (s *MemoryStore) UpdateDraft(_ context.Context, d Draft) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.drafts[d.ID]
	if !ok {
		return Draft{}, ErrNotFound
	}
	existing.Name = d.Name
	existing.Description = d.Description
	existing.RegoSource = d.RegoSource
	existing.UpdatedAt = time.Now().UTC()
	// Tenant + CreatedAt + CreatedBy are deliberately not overwritten.
	s.drafts[d.ID] = existing
	return existing, nil
}

// GetDraft returns the draft (regardless of tenant; the handler is
// responsible for tenant-scoping reads).
func (s *MemoryStore) GetDraft(_ context.Context, id string) (Draft, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.drafts[id]
	if !ok {
		return Draft{}, ErrNotFound
	}
	return d, nil
}

// ListDrafts returns drafts most-recent-first. Tenant filter on the
// filter parameter scopes results; empty Tenant returns ALL drafts
// (superadmin view).
func (s *MemoryStore) ListDrafts(_ context.Context, filter ListFilter) ([]Draft, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Draft, 0, len(s.drafts))
	for _, d := range s.drafts {
		if filter.Tenant != "" && d.Tenant != filter.Tenant {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if filter.Offset >= len(out) {
		return []Draft{}, nil
	}
	end := filter.Offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[filter.Offset:end], nil
}

// DeleteDraft removes the row. Refuses when ANY tenant's active
// pointer references the draft as current OR previous; promoting
// away from the row first is the operator's escape hatch. The
// sweep over every per-tenant active row is O(N tenants), fine at
// expected scales (admin RPS is essentially zero).
func (s *MemoryStore) DeleteDraft(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.drafts[id]; !ok {
		return ErrNotFound
	}
	for _, a := range s.active {
		if a.CurrentDraftID == id || a.PreviousDraftID == id {
			return ErrActiveDraftDelete
		}
	}
	delete(s.drafts, id)
	return nil
}

// GetActive returns the active pointer for the given tenant. Empty
// tenant returns the default-fallback row. Missing rows return a
// zero-value Active (with no error) — the caller distinguishes
// "no active set" via CurrentDraftID == "".
func (s *MemoryStore) GetActive(_ context.Context, tenant string) (Active, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := s.active[tenant]
	a.Tenant = tenant // make sure the response carries the key
	return a, nil
}

// ListActive returns every tenant's active pointer. Ordered with
// the default-fallback row (empty tenant) first so callers that
// install engines in order (startup hydration) get the fallback
// before per-tenant overlays.
func (s *MemoryStore) ListActive(_ context.Context) ([]Active, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Active, 0, len(s.active))
	// Default fallback first if present.
	if def, ok := s.active[""]; ok {
		def.Tenant = ""
		out = append(out, def)
	}
	// Then per-tenant rows in deterministic order by tenant name.
	tenants := make([]string, 0, len(s.active))
	for t := range s.active {
		if t == "" {
			continue
		}
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	for _, t := range tenants {
		a := s.active[t]
		a.Tenant = t
		out = append(out, a)
	}
	return out, nil
}

// Promote sets the given tenant's CurrentDraftID = draftID and
// moves the existing current onto PreviousDraftID. Validates the
// draft exists inside the same critical section so a concurrent
// delete can't slip between the existence check and the pointer
// write. Empty tenant operates on the default-fallback row.
//
// Promoting the already-current draft is a no-op: the pointer is
// returned unchanged and the timestamps are not refreshed.
func (s *MemoryStore) Promote(_ context.Context, draftID, promotedBy, tenant string) (Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.drafts[draftID]; !ok {
		return Active{}, ErrNotFound
	}
	current := s.active[tenant]
	if current.CurrentDraftID == draftID {
		current.Tenant = tenant
		return current, nil
	}
	next := Active{
		Tenant:          tenant,
		CurrentDraftID:  draftID,
		PreviousDraftID: current.CurrentDraftID,
		PromotedAt:      time.Now().UTC(),
		PromotedBy:      promotedBy,
	}
	s.active[tenant] = next
	s.notifyWatchers(next)
	return next, nil
}

// Rollback swaps Current and Previous for the given tenant, then
// clears Previous so a second consecutive rollback returns
// ErrNotFound rather than ping-ponging. Empty tenant operates on
// the default-fallback row. ErrNotFound is returned when there is
// nothing to roll back to.
func (s *MemoryStore) Rollback(_ context.Context, rolledBackBy, tenant string) (Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.active[tenant]
	if current.PreviousDraftID == "" {
		return Active{}, ErrNotFound
	}
	next := Active{
		Tenant:          tenant,
		CurrentDraftID:  current.PreviousDraftID,
		PreviousDraftID: "", // one-step rollback; clear to avoid ping-pong
		PromotedAt:      time.Now().UTC(),
		PromotedBy:      rolledBackBy,
	}
	s.active[tenant] = next
	s.notifyWatchers(next)
	return next, nil
}

// DeleteActive clears the tenant's active-policy pointer row.
// Empty tenant is a no-op (we don't want to leave the default-
// fallback slot without a row in the table). Idempotent: clearing
// an empty row returns the zero-value Active without error.
//
// Fan-out: subscribers receive an Active with empty CurrentDraftID
// and the affected tenant; the watcher in main.go treats that
// payload as a "drop the slot" signal and calls Reloader.RemoveFor.
func (s *MemoryStore) DeleteActive(_ context.Context, tenant string) (Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tenant == "" {
		// No-op: the default-fallback row is special. To "reset" it
		// the operator promotes a different draft.
		return s.active[""], nil
	}

	cleared := Active{Tenant: tenant}
	delete(s.active, tenant)
	s.notifyWatchers(cleared)
	return cleared, nil
}
