package policystore

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPostgresStore_CrossReplicaWatch exercises the real LISTEN/
// NOTIFY path that the in-memory tests can't reach. It's gated on
// INTENTGATE_TEST_POSTGRES_URL so CI runs without a Postgres are
// a skip, not a failure — matches the convention used by
// revocation/store_test.go.
//
// Setup: two PostgresStore instances opened against the same DSN
// (representing two gateway replicas sharing a database). Promote
// on store A; expect store B's Watch channel to receive the
// active value within a tight deadline (the NOTIFY round-trip on
// a co-located Postgres is sub-millisecond; we allow 2s for CI
// jitter).
//
// The polling fallback is exercised separately by sleeping past
// pollFallbackInterval with one store's listener forcibly killed
// — that's a future test if the LISTEN path proves flaky in CI.
func TestPostgresStore_CrossReplicaWatch(t *testing.T) {
	dsn := os.Getenv("INTENTGATE_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INTENTGATE_TEST_POSTGRES_URL not set; skipping cross-replica test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Replica A — the one issuing the promote.
	a, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open store A: %v", err)
	}
	defer a.Close()

	// Replica B — the one watching for the change.
	b, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open store B: %v", err)
	}
	defer b.Close()

	// Subscribe on B BEFORE promoting on A so the LISTEN session is
	// already wired by the time the NOTIFY fires. If we ran the
	// promote first the notify could land before B's listener was
	// registered — the 5s polling fallback would still pick it up,
	// but the test would be slower and harder to interpret.
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	ch, err := b.Watch(watchCtx)
	if err != nil {
		t.Fatalf("watch on B: %v", err)
	}
	// Give B's listener a beat to LISTEN before we promote.
	time.Sleep(200 * time.Millisecond)

	// Seed a draft on A and promote it.
	d, err := a.CreateDraft(ctx, Draft{Name: "cross-replica", RegoSource: validRego})
	if err != nil {
		t.Fatalf("create draft on A: %v", err)
	}
	defer func() { _ = a.DeleteDraft(ctx, d.ID) }() // best-effort cleanup
	// Pre-promote: clear any prior active state so this test is
	// self-contained. We can't easily "reset" the policy_active
	// row from outside the API; instead we just promote and check
	// the resulting CurrentDraftID matches.
	if _, err := a.Promote(ctx, d.ID, "cross-replica-test"); err != nil {
		t.Fatalf("promote on A: %v", err)
	}

	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatal("watch channel closed before delivery")
		}
		if got.CurrentDraftID != d.ID {
			t.Fatalf("B observed CurrentDraftID=%q, want %q", got.CurrentDraftID, d.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B did not observe the promote within 2s — NOTIFY path likely broken")
	}
}

// TestPostgresStore_WatchClosesOnStoreClose makes sure the watch
// channel is closed when the store is shut down, so a caller
// ranging over it sees a clean exit instead of hanging.
func TestPostgresStore_WatchClosesOnStoreClose(t *testing.T) {
	dsn := os.Getenv("INTENTGATE_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INTENTGATE_TEST_POSTGRES_URL not set; skipping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ch, err := s.Watch(context.Background())
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = s.Close()
	}()
	select {
	case _, open := <-ch:
		if open {
			// Got a stray value, keep draining until close.
			for range ch { //nolint:revive
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch channel did not close after store Close")
	}
}
