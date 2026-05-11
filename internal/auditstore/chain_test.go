package auditstore

import (
	"context"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

func mkChainEvent(t time.Time, decision audit.Decision, tool, tenant string) audit.Event {
	e := audit.NewEvent(decision, tool)
	e.Timestamp = t.UTC().Format(time.RFC3339Nano)
	e.Tenant = tenant
	e.AgentID = "agent-a"
	return e
}

// --- happy path -----------------------------------------------------

func TestVerifyChainHappyPath(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		ev := mkChainEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "read", "acme")
		if err := s.Insert(ctx, ev); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	result, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "acme"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.OK {
		t.Errorf("expected OK, got %+v", result)
	}
	if result.Verified != 5 {
		t.Errorf("verified=%d want 5", result.Verified)
	}
	if result.BrokenAt != nil {
		t.Errorf("expected no break, got %+v", result.BrokenAt)
	}
}

// --- chain isolation between tenants --------------------------------

func TestVerifyChainPerTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)

	now := time.Now().UTC()
	// Interleave acme + globex events.
	for i := 0; i < 5; i++ {
		_ = s.Insert(ctx, mkChainEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "x", "acme"))
		_ = s.Insert(ctx, mkChainEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "y", "globex"))
	}

	for _, tenant := range []string{"acme", "globex"} {
		r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: tenant})
		if err != nil {
			t.Fatalf("verify %s: %v", tenant, err)
		}
		if !r.OK || r.Verified != 5 {
			t.Errorf("%s: ok=%v verified=%d want true/5; got %+v", tenant, r.OK, r.Verified, r)
		}
	}
}

// --- tampered hash --------------------------------------------------

func TestVerifyChainDetectsTamperedHash(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		_ = s.Insert(ctx, mkChainEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "x", "acme"))
	}

	// Tamper with the second row's stored hash.
	s.tamperHashAt(1, "0000000000000000000000000000000000000000000000000000000000000000")

	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "acme"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK {
		t.Fatalf("expected !OK after tamper, got %+v", r)
	}
	if r.BrokenAt == nil {
		t.Fatalf("expected BrokenAt, got nil")
	}
	if r.BrokenAt.Reason == "" {
		t.Errorf("expected reason populated")
	}
}

// --- tampered event body --------------------------------------------

func TestVerifyChainDetectsTamperedEventBody(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_ = s.Insert(ctx, mkChainEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionBlock, "delete_db", "acme"))
	}

	// Tamper with the second row's reason without touching the hash.
	s.tamperEventAt(1, func(e *audit.Event) {
		e.Reason = "tampered reason — this should break the chain"
	})

	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "acme"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.OK {
		t.Fatalf("expected !OK after body tamper, got %+v", r)
	}
	if r.BrokenAt == nil {
		t.Fatalf("expected BrokenAt, got nil")
	}
	if r.BrokenAt.StoredHash == r.BrokenAt.ExpectedHash {
		t.Errorf("stored == expected hash, expected divergence: %+v", r.BrokenAt)
	}
}

// --- empty chain ----------------------------------------------------

func TestVerifyChainEmpty(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)
	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Verified != 0 {
		t.Errorf("empty chain should verify trivially: %+v", r)
	}
}

// --- default tenant fallback ----------------------------------------

func TestVerifyChainDefaultTenant(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)
	now := time.Now().UTC()
	// Event with explicitly empty Tenant — chain key falls back to "default".
	ev := mkChainEvent(now, audit.DecisionAllow, "x", "")
	_ = s.Insert(ctx, ev)

	// Verify with empty tenant in filter also falls back to "default".
	r, err := s.VerifyChain(ctx, VerifyFilter{Tenant: ""})
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Verified != 1 {
		t.Errorf("default-tenant fallback failed: %+v", r)
	}
}

// --- ComputeHash determinism ----------------------------------------

func TestComputeHashDeterministic(t *testing.T) {
	ev := mkChainEvent(time.Date(2026, 5, 11, 22, 30, 0, 0, time.UTC), audit.DecisionAllow, "transfer_funds", "acme")
	ev.AgentID = "fin-bot"
	ev.Reason = "under threshold"

	h1, err := audit.HashEvent("prev-hash-abc", ev)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := audit.HashEvent("prev-hash-abc", ev)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic hash: %s vs %s", h1, h2)
	}

	// Different prev = different hash.
	h3, err := audit.HashEvent("different-prev", ev)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Errorf("hash should depend on prev_hash; got identical %s", h1)
	}

	// Same prev, different event body = different hash.
	ev2 := ev
	ev2.Reason = "over threshold"
	h4, _ := audit.HashEvent("prev-hash-abc", ev2)
	if h1 == h4 {
		t.Errorf("hash should depend on body; got identical %s", h1)
	}
}

// --- elevation_id participates in the chain --------------------------

// Two events that differ only in elevation_id MUST produce different
// hashes — otherwise an attacker could swap the elevation row out of
// from under an audited action and the chain would still verify.
func TestChainHashCoversElevationID(t *testing.T) {
	now := time.Date(2026, 5, 11, 22, 30, 0, 0, time.UTC)
	a := mkChainEvent(now, audit.DecisionAllow, "admin/mint", "acme")
	a.ElevationID = "elev-abc-123"
	b := mkChainEvent(now, audit.DecisionAllow, "admin/mint", "acme")
	b.ElevationID = "elev-xyz-789"

	ha, err := audit.HashEvent("prev", a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := audit.HashEvent("prev", b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Errorf("elevation_id should affect the chain hash; got identical %s", ha)
	}
}

// Memory-store filter honors ElevationID. Two events with different
// elevations; filtering returns only the matching one.
func TestMemoryStoreFiltersByElevationID(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)

	now := time.Now().UTC()
	e1 := mkChainEvent(now, audit.DecisionAllow, "admin/mint", "acme")
	e1.ElevationID = "elev-1"
	e2 := mkChainEvent(now.Add(time.Second), audit.DecisionAllow, "admin/revoke", "acme")
	e2.ElevationID = "elev-2"
	e3 := mkChainEvent(now.Add(2*time.Second), audit.DecisionAllow, "admin/mint", "acme")
	// no elevation_id on e3 — this row should never match a non-empty filter.
	_ = s.Insert(ctx, e1)
	_ = s.Insert(ctx, e2)
	_ = s.Insert(ctx, e3)

	got, err := s.Query(ctx, QueryFilter{ElevationID: "elev-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("want 1 event for elev-1, got %d", len(got))
	}
}

// --- window filter --------------------------------------------------

func TestVerifyChainRespectsWindow(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)
	t0 := time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		_ = s.Insert(ctx, mkChainEvent(t0.Add(time.Duration(i)*time.Hour), audit.DecisionAllow, "x", "acme"))
	}

	r, err := s.VerifyChain(ctx, VerifyFilter{
		Tenant: "acme",
		From:   t0.Add(2 * time.Hour),
		To:     t0.Add(5 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK {
		t.Errorf("window-scoped verify should succeed: %+v", r)
	}
	if r.Verified != 4 {
		t.Errorf("expected 4 events in [2h, 5h], got %d", r.Verified)
	}
}
