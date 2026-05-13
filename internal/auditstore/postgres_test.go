package auditstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres-backed regression tests for the audit chain.
//
// Gated on INTENTGATE_TEST_POSTGRES_URL (same convention as
// policystore/postgres_test.go and revocation/store_test.go). CI
// without a Postgres → skip, not failure.
//
// Every test in this file drops the audit_events + audit_chain_heads
// tables FIRST so the migration runs against a truly empty database.
// The bugs these tests pin were latent precisely because the existing
// suite reused a long-lived test DB whose schema had already been
// applied at some earlier version — exactly what a customer's
// brand-new Postgres deployment WON'T have.
//
// These three tests would have caught every bug v1.6.1 fixes:
//
//   TestPostgresStore_FreshMigrate_SeedDoesNotPanic
//       v1.6.0 schema.sql in policystore lacked PRIMARY KEY (tenant)
//       on policy_active; fresh installs hit SQLSTATE 42P10 on the
//       seed insert. The audit_events schema has its own variants
//       of the same risk (FK references, ON CONFLICT clauses), so
//       we exercise the migration end-to-end here too as a guard.
//
//   TestPostgresStore_VerifyChain_NormalEvent
//       v1.6.0 wrote the canonical hash over RFC3339Nano-9 but
//       Postgres TIMESTAMPTZ stored at microsecond precision, so
//       VerifyChain's recompute (from the round-tripped time.Time)
//       always failed on row 1.
//
//   TestPostgresStore_VerifyChain_EscalateEvent
//       v1.6.0 had PendingID/DecidedBy/RequiresStepUp in the
//       canonical hash but no corresponding schema columns and no
//       Scan in VerifyChain. Escalate events broke the chain.

func newTestPostgresStore(t *testing.T) (*PostgresStore, func()) {
	t.Helper()
	dsn := os.Getenv("INTENTGATE_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INTENTGATE_TEST_POSTGRES_URL not set; skipping postgres-backed audit tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Drop the chain tables first so the migration runs from zero on
	// every test. We use a throwaway pgx pool rather than the
	// store-internal one because PostgresStore.Migrate() runs DURING
	// NewPostgresStore — by the time we have the store, the schema
	// is already applied and dropping mid-test would leave the pool
	// pointing at dropped tables.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("dial postgres for cleanup: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS audit_chain_heads, audit_events CASCADE`); err != nil {
		pool.Close()
		t.Fatalf("drop audit tables: %v", err)
	}
	pool.Close()

	storeCtx, storeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	s, err := NewPostgresStore(storeCtx, dsn)
	if err != nil {
		storeCancel()
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return s, func() {
		s.Close()
		storeCancel()
	}
}

// TestPostgresStore_FreshMigrate_SeedDoesNotPanic exercises the full
// migration path against an empty database. v1.6.0 didn't fail HERE
// (audit_events has no seed insert with ON CONFLICT), but if a
// similar bug ever lands the test will catch it.
func TestPostgresStore_FreshMigrate_SeedDoesNotPanic(t *testing.T) {
	s, cleanup := newTestPostgresStore(t)
	defer cleanup()

	// Smoke: Insert one event to confirm the schema is actually
	// usable, not just successfully migrated.
	ctx := context.Background()
	ev := audit.NewEvent(audit.DecisionAllow, "smoke")
	ev.Tenant = "default"
	if err := s.Insert(ctx, ev); err != nil {
		t.Fatalf("Insert after fresh migrate: %v", err)
	}
}

// TestPostgresStore_VerifyChain_NormalEvent inserts a single normal
// (non-escalate) audit event and verifies the chain. v1.6.0 failed
// this on the very first row because of the RFC3339Nano-vs-
// TIMESTAMPTZ precision mismatch.
func TestPostgresStore_VerifyChain_NormalEvent(t *testing.T) {
	s, cleanup := newTestPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	ev := audit.NewEvent(audit.DecisionAllow, "read_invoice")
	ev.Tenant = "default"
	ev.AgentID = "agent-a"
	ev.Reason = "read-only tool"
	if err := s.Insert(ctx, ev); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "default"})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !r.OK {
		t.Fatalf("chain not ok; broken_at=%+v", r.BrokenAt)
	}
	if r.Verified != 1 {
		t.Errorf("verified=%d; want 1", r.Verified)
	}
}

// TestPostgresStore_VerifyChain_EscalateEvent pins the bug class
// where canonical-hash fields aren't persisted. v1.6.0 wrote
// PendingID/DecidedBy/RequiresStepUp into the canonical bytes at
// insert time but had no schema columns to recover those values on
// verify, so the chain broke at the first escalate event.
func TestPostgresStore_VerifyChain_EscalateEvent(t *testing.T) {
	s, cleanup := newTestPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	ev := audit.NewEvent(audit.DecisionEscalate, "transfer_funds")
	ev.Tenant = "default"
	ev.AgentID = "agent-finance"
	ev.Reason = "escalate: transfer at or above 5000 EUR threshold"
	ev.PendingID = "pending-abc-123"
	ev.RequiresStepUp = true
	if err := s.Insert(ctx, ev); err != nil {
		t.Fatalf("Insert escalate event: %v", err)
	}

	// Insert a follow-up "approved by operator" event with DecidedBy
	// populated. This is the second half of the approval flow and
	// the v1.6.0 schema also couldn't round-trip DecidedBy.
	follow := audit.NewEvent(audit.DecisionAllow, "transfer_funds")
	follow.Tenant = "default"
	follow.AgentID = "agent-finance"
	follow.Reason = "approved by operator@local"
	follow.PendingID = "pending-abc-123"
	follow.DecidedBy = "operator@local"
	if err := s.Insert(ctx, follow); err != nil {
		t.Fatalf("Insert follow-up: %v", err)
	}

	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "default"})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !r.OK {
		t.Fatalf("chain not ok after escalate; broken_at=%+v", r.BrokenAt)
	}
	if r.Verified != 2 {
		t.Errorf("verified=%d; want 2", r.Verified)
	}
}

// TestPostgresStore_VerifyChain_DetectsActualTampering confirms the
// chain still catches real tampering after the v1.6.1 fixes — we
// haven't accidentally weakened tamper detection by loosening the
// canonical form.
func TestPostgresStore_VerifyChain_DetectsActualTampering(t *testing.T) {
	s, cleanup := newTestPostgresStore(t)
	defer cleanup()
	ctx := context.Background()

	ev := audit.NewEvent(audit.DecisionAllow, "read_invoice")
	ev.Tenant = "default"
	ev.AgentID = "agent-a"
	if err := s.Insert(ctx, ev); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Mutate the stored row directly — simulate an attacker
	// rewriting the reason after the fact. The chain should detect
	// this on the next verify.
	if _, err := s.pool.Exec(ctx,
		`UPDATE audit_events SET reason = 'rewritten' WHERE id = 1`,
	); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "default"})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if r.OK {
		t.Fatal("chain ok after tampering; expected broken")
	}
	if r.BrokenAt == nil || r.BrokenAt.Reason != "hash mismatch (row body tampered)" {
		t.Errorf("unexpected break reason: %+v", r.BrokenAt)
	}
}
