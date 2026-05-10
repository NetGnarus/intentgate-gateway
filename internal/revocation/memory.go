package revocation

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore keeps revocations in a process-local map. Lost on
// gateway restart, not shared across replicas, fine for dev and
// single-node installs that accept the trade-off.
//
// Storage layout: outer map keyed by JTI, inner map keyed by tenant
// (with "" reserved for superadmin / global revocations). This
// matches the Postgres composite primary key (jti, tenant) so the
// two backends agree on how cross-tenant revocations isolate.
//
// Safe for concurrent use.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]map[string]RevokedToken
}

// NewMemoryStore returns an empty in-memory revocation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]map[string]RevokedToken)}
}

// IsRevoked returns true when either:
//   - A row exists for (jti, tenant) — the caller's own tenant
//     revoked this token.
//   - A row exists for (jti, "")     — the superadmin revoked this
//     token globally; affects every tenant.
//
// O(1) on both lookups.
func (s *MemoryStore) IsRevoked(_ context.Context, jti, tenant string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byTenant, ok := s.entries[jti]
	if !ok {
		return false, nil
	}
	if _, ok := byTenant[tenant]; ok {
		return true, nil
	}
	if tenant != "" {
		if _, ok := byTenant[""]; ok {
			return true, nil
		}
	}
	return false, nil
}

// Revoke is idempotent per (jti, tenant). Re-revoking with a
// different reason updates the stored reason but keeps the original
// RevokedAt timestamp — operators adding context to an existing
// revocation expect the original time to stick.
//
// Different tenants revoking the same JTI store independent rows;
// neither overwrites the other.
func (s *MemoryStore) Revoke(_ context.Context, jti, reason, tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byTenant, ok := s.entries[jti]
	if !ok {
		byTenant = make(map[string]RevokedToken)
		s.entries[jti] = byTenant
	}
	if existing, ok := byTenant[tenant]; ok {
		existing.Reason = reason
		byTenant[tenant] = existing
		return nil
	}
	byTenant[tenant] = RevokedToken{
		JTI:       jti,
		RevokedAt: time.Now().UTC(),
		Reason:    reason,
		Tenant:    tenant,
	}
	return nil
}

// List returns revocations sorted most-recent-first.
//
// tenant=="" returns ALL rows (superadmin view). A non-empty tenant
// returns only that tenant's rows; superadmin-issued rows (stored
// with empty tenant) are NOT visible to per-tenant admins. This
// matches the behavior every prior version of the chart documented.
func (s *MemoryStore) List(_ context.Context, tenant string, limit, offset int) ([]RevokedToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]RevokedToken, 0)
	for _, byTenant := range s.entries {
		for rowTenant, e := range byTenant {
			if tenant != "" && rowTenant != tenant {
				continue
			}
			all = append(all, e)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].RevokedAt.After(all[j].RevokedAt)
	})

	if offset >= len(all) {
		return []RevokedToken{}, nil
	}
	end := offset + limit
	if limit <= 0 || end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}
