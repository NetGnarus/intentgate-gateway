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
// Safe for concurrent use.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]RevokedToken
}

// NewMemoryStore returns an empty in-memory revocation store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]RevokedToken)}
}

// IsRevoked is O(1).
func (s *MemoryStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entries[jti]
	return ok, nil
}

// Revoke is idempotent. Re-revoking with a different reason updates the
// stored reason but keeps the original RevokedAt timestamp — operators
// adding context to an existing revocation expect the original time
// to stick. Tenant is recorded on first insert and not overwritten —
// the original revoker's tenant is the authoritative attribution.
func (s *MemoryStore) Revoke(_ context.Context, jti, reason, tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[jti]; ok {
		existing.Reason = reason
		s.entries[jti] = existing
		return nil
	}
	s.entries[jti] = RevokedToken{
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
// returns only that tenant's rows; rows with empty tenant (legacy /
// superadmin-issued) are NOT visible to per-tenant admins.
func (s *MemoryStore) List(_ context.Context, tenant string, limit, offset int) ([]RevokedToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]RevokedToken, 0, len(s.entries))
	for _, e := range s.entries {
		if tenant != "" && e.Tenant != tenant {
			continue
		}
		all = append(all, e)
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
