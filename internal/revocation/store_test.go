package revocation

import (
	"context"
	"os"
	"testing"
)

// runStoreContract exercises the Store interface against any backend.
// Both MemoryStore and (when an env var is set) PostgresStore call
// through this so behavioral drift between implementations gets
// caught immediately.
func runStoreContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	// Initially revoked? No. Use the empty tenant ("" = superadmin
	// scope) for the simple cases; a later subtest covers the
	// per-tenant scoping invariants explicitly.
	if revoked, err := s.IsRevoked(ctx, "fresh-jti", ""); err != nil || revoked {
		t.Fatalf("fresh JTI: revoked=%v err=%v; want false, nil", revoked, err)
	}

	// Revoke; revoking twice is a no-op (idempotent).
	if err := s.Revoke(ctx, "tok1", "leaked", ""); err != nil {
		t.Fatalf("Revoke 1: %v", err)
	}
	if err := s.Revoke(ctx, "tok1", "leaked", ""); err != nil {
		t.Fatalf("Revoke 2 (idempotent): %v", err)
	}

	if revoked, err := s.IsRevoked(ctx, "tok1", ""); err != nil || !revoked {
		t.Fatalf("tok1: revoked=%v err=%v; want true, nil", revoked, err)
	}

	// A different JTI is unaffected.
	if revoked, err := s.IsRevoked(ctx, "tok2", ""); err != nil || revoked {
		t.Fatalf("tok2: revoked=%v err=%v; want false, nil", revoked, err)
	}

	// Revoke a few more so List has something to sort. Mix tenants to
	// also exercise per-tenant filtering at the contract level.
	if err := s.Revoke(ctx, "tok2", "agent compromise", "acme"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "tok3", "", "globex"); err != nil {
		t.Fatal(err)
	}

	list, err := s.List(ctx, "", 10, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) < 3 {
		t.Fatalf("List returned %d entries; want at least 3", len(list))
	}
	// Most-recent first: tok3 (last revoked) should come before tok1.
	t3idx, t1idx := -1, -1
	for i, rt := range list {
		switch rt.JTI {
		case "tok3":
			t3idx = i
		case "tok1":
			t1idx = i
		}
	}
	if t3idx == -1 || t1idx == -1 {
		t.Fatalf("List missing entries: tok3=%d tok1=%d list=%+v", t3idx, t1idx, list)
	}
	if t3idx >= t1idx {
		t.Errorf("List should be most-recent first: tok3 at %d, tok1 at %d", t3idx, t1idx)
	}

	// Pagination: offset past the end returns empty, not error.
	page, err := s.List(ctx, "", 10, 1000)
	if err != nil {
		t.Fatalf("List with high offset: %v", err)
	}
	if len(page) != 0 {
		t.Errorf("List with high offset: got %d entries, want 0", len(page))
	}

	// Per-tenant filter: acme admin sees only tok2, not tok1 (no
	// tenant) or tok3 (different tenant).
	acme, err := s.List(ctx, "acme", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(acme) != 1 || acme[0].JTI != "tok2" {
		t.Errorf("acme List: %+v want [tok2]", acme)
	}

	// Reason update preserves original revoked_at semantics.
	// (We can't assert on RevokedAt directly across implementations
	// without races, but we can confirm the new reason is observable.)
	if err := s.Revoke(ctx, "tok1", "updated reason", ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx, "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range got {
		if rt.JTI == "tok1" && rt.Reason != "updated reason" {
			t.Errorf("tok1 reason: got %q want %q", rt.Reason, "updated reason")
		}
	}
}

// runTenantScopingContract exercises the cross-tenant isolation
// guarantees added in gateway 1.0.1: a per-tenant admin's revocation
// only affects their own tenant on the hot path, while a superadmin
// revocation (tenant="") still applies globally. Closes the
// cross-tenant denial-of-service vector that existed in 1.0.
func runTenantScopingContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	// The adversarial setup: an "attacker" tenant (acme) tries to
	// revoke a JTI that belongs to a "victim" tenant (globex). Pre-
	// 1.0.1, this would have caused globex's hot path to deny the
	// token. We assert the opposite: globex is unaffected.
	if err := s.Revoke(ctx, "victim-jti", "adversarial revoke", "acme"); err != nil {
		t.Fatalf("acme adversarial revoke: %v", err)
	}
	revokedForGlobex, err := s.IsRevoked(ctx, "victim-jti", "globex")
	if err != nil {
		t.Fatalf("IsRevoked(victim, globex): %v", err)
	}
	if revokedForGlobex {
		t.Error("cross-tenant DoS hole still open: acme revoke affected globex hot path")
	}
	// Acme itself does see its own revocation row, naturally.
	revokedForAcme, err := s.IsRevoked(ctx, "victim-jti", "acme")
	if err != nil {
		t.Fatalf("IsRevoked(victim, acme): %v", err)
	}
	if !revokedForAcme {
		t.Error("acme's own revocation row not honored on its own hot path")
	}

	// Legitimate same-tenant revoke: globex revokes its own JTI and
	// the hot path picks it up. Crucially, this works even though
	// acme already wrote a row for the same JTI under the attacker's
	// tenant — different (jti, tenant) keys, no collision.
	if err := s.Revoke(ctx, "victim-jti", "legitimate revoke", "globex"); err != nil {
		t.Fatalf("globex legitimate revoke: %v", err)
	}
	revokedForGlobex, err = s.IsRevoked(ctx, "victim-jti", "globex")
	if err != nil {
		t.Fatal(err)
	}
	if !revokedForGlobex {
		t.Error("globex's legitimate revoke didn't take effect")
	}

	// Superadmin scope still propagates globally. A revoke with
	// tenant="" must affect every tenant's hot path; this is the
	// emergency stop the operator pulls when the token holder is
	// unknown or the breach is cross-tenant.
	if err := s.Revoke(ctx, "global-jti", "data leak", ""); err != nil {
		t.Fatalf("superadmin revoke: %v", err)
	}
	for _, tenant := range []string{"acme", "globex", "default"} {
		revoked, err := s.IsRevoked(ctx, "global-jti", tenant)
		if err != nil {
			t.Fatalf("IsRevoked(global-jti, %s): %v", tenant, err)
		}
		if !revoked {
			t.Errorf("superadmin revoke didn't propagate to tenant=%s", tenant)
		}
	}

	// Same-tenant idempotency is preserved: re-revoking with a
	// different reason updates the reason, doesn't error.
	if err := s.Revoke(ctx, "victim-jti", "updated reason", "globex"); err != nil {
		t.Fatalf("globex re-revoke: %v", err)
	}
	all, err := s.List(ctx, "globex", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range all {
		if rt.JTI == "victim-jti" && rt.Reason != "updated reason" {
			t.Errorf("globex re-revoke reason: got %q want %q", rt.Reason, "updated reason")
		}
	}
}

func TestMemoryStore_Contract(t *testing.T) {
	runStoreContract(t, NewMemoryStore())
}

func TestMemoryStore_TenantScoping(t *testing.T) {
	runTenantScopingContract(t, NewMemoryStore())
}

// TestPostgresStore_Contract runs the contract against a live
// Postgres. Skipped unless INTENTGATE_TEST_POSTGRES_URL is set, so CI
// without a database doesn't fail — operators verifying the store on
// their own infra can opt in.
//
// Local dev:
//
//	docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=test postgres:17
//	export INTENTGATE_TEST_POSTGRES_URL=postgres://postgres:test@localhost:5432/postgres
//	go test ./internal/revocation/...
func TestPostgresStore_Contract(t *testing.T) {
	dsn := os.Getenv("INTENTGATE_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("INTENTGATE_TEST_POSTGRES_URL not set; skipping Postgres integration test")
	}

	ctx := context.Background()
	store, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer store.Close()

	// Clean any leftover state from previous runs.
	if _, err := store.pool.Exec(ctx, "DELETE FROM revoked_tokens WHERE jti IN ('fresh-jti','tok1','tok2','tok3','victim-jti','global-jti')"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	runStoreContract(t, store)
	runTenantScopingContract(t, store)
}
