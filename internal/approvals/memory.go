package approvals

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// MemoryStore keeps pending requests in a process-local map and uses
// per-id channels to wake Wait when a decision arrives. Lost on
// gateway restart; not shared across replicas.
//
// Safe for concurrent use.
type MemoryStore struct {
	mu   sync.Mutex
	rows map[string]*memRow
}

type memRow struct {
	req  PendingRequest
	wake chan struct{} // closed when status leaves pending
}

// NewMemoryStore returns an empty store ready for use.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: make(map[string]*memRow)}
}

// Enqueue assigns a PendingID (if the caller didn't), stamps
// CreatedAt + StatusPending, and stores the row.
func (s *MemoryStore) Enqueue(ctx context.Context, req PendingRequest) (PendingRequest, error) {
	if req.PendingID == "" {
		id, err := NewPendingID()
		if err != nil {
			return PendingRequest{}, err
		}
		req.PendingID = id
	}
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now().UTC()
	}
	req.Status = StatusPending

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rows[req.PendingID]; exists {
		return PendingRequest{}, errors.New("approvals: duplicate pending_id")
	}
	s.rows[req.PendingID] = &memRow{
		req:  req,
		wake: make(chan struct{}),
	}
	return req, nil
}

// Wait blocks until the row leaves pending OR ctx is cancelled. On
// cancellation the row is marked StatusTimeout and returned; the
// caller emits the final audit event.
func (s *MemoryStore) Wait(ctx context.Context, pendingID string) (PendingRequest, error) {
	s.mu.Lock()
	row, ok := s.rows[pendingID]
	s.mu.Unlock()
	if !ok {
		return PendingRequest{}, ErrNotFound
	}

	select {
	case <-row.wake:
		s.mu.Lock()
		defer s.mu.Unlock()
		return row.req, nil
	case <-ctx.Done():
		// Mark timeout. Decide-after-timeout becomes a no-op (the
		// channel is already closed below).
		s.mu.Lock()
		defer s.mu.Unlock()
		// Re-check status under the lock — a Decide may have raced us.
		if row.req.Status == StatusPending {
			now := time.Now().UTC()
			row.req.Status = StatusTimeout
			row.req.DecidedAt = &now
			close(row.wake)
		}
		return row.req, nil
	}
}

// Decide records an approve/reject and wakes any Wait. Idempotent:
// a second Decide returns ErrAlreadyDecided without state change.
func (s *MemoryStore) Decide(ctx context.Context, pendingID string, dec Decision) (PendingRequest, error) {
	if dec.Status != StatusApproved && dec.Status != StatusRejected {
		return PendingRequest{}, errors.New("approvals: decision must be approved or rejected")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[pendingID]
	if !ok {
		return PendingRequest{}, ErrNotFound
	}
	if row.req.Status != StatusPending {
		return row.req, ErrAlreadyDecided
	}

	now := time.Now().UTC()
	row.req.Status = dec.Status
	row.req.DecidedAt = &now
	row.req.DecidedBy = dec.DecidedBy
	row.req.DecideNote = dec.Note
	close(row.wake)
	return row.req, nil
}

// Get returns a single row.
func (s *MemoryStore) Get(_ context.Context, pendingID string) (PendingRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[pendingID]
	if !ok {
		return PendingRequest{}, ErrNotFound
	}
	return row.req, nil
}

// List returns rows matching the filter, most-recent first.
func (s *MemoryStore) List(_ context.Context, f ListFilter) ([]PendingRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all := make([]PendingRequest, 0, len(s.rows))
	for _, r := range s.rows {
		if f.Status != "" && r.req.Status != f.Status {
			continue
		}
		all = append(all, r.req)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(all) {
		return []PendingRequest{}, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

// Close is a no-op; satisfies Store.
func (s *MemoryStore) Close() error { return nil }
