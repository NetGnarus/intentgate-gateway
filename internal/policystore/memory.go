package policystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// MemoryStore keeps drafts and the active pointer in process-local
// maps. Single-replica only, lost on restart. Production deployments
// supply [PostgresStore].
//
// Safe for concurrent use; one mutex guards every field. Contention
// is fine: policy authoring is operator-driven (RPS << 1).
type MemoryStore struct {
	mu     sync.RWMutex
	drafts map[string]Draft
	active Active
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{drafts: make(map[string]Draft)}
}

// Close is a no-op (no resources to release).
func (s *MemoryStore) Close() error { return nil }

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

// DeleteDraft removes the row. Refuses when the active pointer
// references the draft as current OR previous; promoting away from
// the row first is the operator's escape hatch.
func (s *MemoryStore) DeleteDraft(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.drafts[id]; !ok {
		return ErrNotFound
	}
	if s.active.CurrentDraftID == id || s.active.PreviousDraftID == id {
		return ErrActiveDraftDelete
	}
	delete(s.drafts, id)
	return nil
}

// GetActive returns the active pointer.
func (s *MemoryStore) GetActive(_ context.Context) (Active, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active, nil
}

// Promote sets CurrentDraftID = draftID and moves the existing
// current onto PreviousDraftID. Validates the draft exists inside
// the same critical section so a concurrent delete can't slip
// between the existence check and the pointer write.
//
// Promoting the already-current draft is a no-op: the pointer is
// returned unchanged and the timestamps are not refreshed. Audit
// emission on the handler side keys off "did Promote change
// anything" via comparing the returned active against the prior
// GetActive — but a simpler check is just "is CurrentDraftID
// different from the requested ID after the call". We chose the
// no-op-on-same-id branch so re-promote spam doesn't churn the
// PromotedAt field.
func (s *MemoryStore) Promote(_ context.Context, draftID, promotedBy string) (Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.drafts[draftID]; !ok {
		return Active{}, ErrNotFound
	}
	if s.active.CurrentDraftID == draftID {
		return s.active, nil
	}
	prev := s.active.CurrentDraftID
	s.active = Active{
		CurrentDraftID:  draftID,
		PreviousDraftID: prev,
		PromotedAt:      time.Now().UTC(),
		PromotedBy:      promotedBy,
	}
	return s.active, nil
}

// Rollback swaps Current and Previous, then clears Previous so a
// second consecutive rollback returns ErrNotFound rather than
// ping-ponging. ErrNotFound is also returned when there is nothing
// to roll back to (a fresh install or after the rollback-clear above).
func (s *MemoryStore) Rollback(_ context.Context, rolledBackBy string) (Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active.PreviousDraftID == "" {
		return Active{}, ErrNotFound
	}
	s.active = Active{
		CurrentDraftID:  s.active.PreviousDraftID,
		PreviousDraftID: "", // one-step rollback; clear to avoid ping-pong
		PromotedAt:      time.Now().UTC(),
		PromotedBy:      rolledBackBy,
	}
	return s.active, nil
}
