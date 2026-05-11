package policystore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// validRego is the minimal Rego the gateway's policy engine accepts.
// Used by tests that don't care about policy content — the store
// itself never compiles, but keeping the source realistic avoids
// surprises when these tests are reused as fixtures elsewhere.
const validRego = `package intentgate.policy
import rego.v1
default decision := {"allow": false, "reason": "default deny"}
`

const validRego2 = `package intentgate.policy
import rego.v1
default decision := {"allow": true, "reason": "v2"}
`

func TestMemoryStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	d, err := s.CreateDraft(ctx, Draft{
		Name:       "first",
		RegoSource: validRego,
		Tenant:     "acme",
		CreatedBy:  "alice",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.ID == "" {
		t.Fatal("created draft has empty ID")
	}
	if d.CreatedAt.IsZero() || d.UpdatedAt.IsZero() {
		t.Fatal("timestamps not populated by store")
	}

	got, err := s.GetDraft(ctx, d.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "first" || got.RegoSource != validRego || got.Tenant != "acme" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	if _, err := s.GetDraft(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_ListTenantScope(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()
	mustCreate := func(name, tenant string) {
		t.Helper()
		if _, err := s.CreateDraft(ctx, Draft{Name: name, RegoSource: validRego, Tenant: tenant}); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
	}
	mustCreate("acme-1", "acme")
	mustCreate("acme-2", "acme")
	mustCreate("globex-1", "globex")
	mustCreate("super-1", "")

	// Superadmin sees all.
	all, err := s.ListDrafts(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("superadmin should see 4 drafts, got %d", len(all))
	}

	// Per-tenant sees only its own.
	acme, err := s.ListDrafts(ctx, ListFilter{Tenant: "acme"})
	if err != nil {
		t.Fatalf("list acme: %v", err)
	}
	if len(acme) != 2 {
		t.Fatalf("acme should see 2 drafts, got %d", len(acme))
	}
	for _, d := range acme {
		if d.Tenant != "acme" {
			t.Fatalf("acme list leaked tenant %q", d.Tenant)
		}
	}
}

func TestMemoryStore_PromoteSetsPrevious(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()
	d1, _ := s.CreateDraft(ctx, Draft{Name: "v1", RegoSource: validRego, Tenant: ""})
	d2, _ := s.CreateDraft(ctx, Draft{Name: "v2", RegoSource: validRego2, Tenant: ""})

	a, err := s.Promote(ctx, d1.ID, "alice", "")
	if err != nil {
		t.Fatalf("promote 1: %v", err)
	}
	if a.CurrentDraftID != d1.ID || a.PreviousDraftID != "" {
		t.Fatalf("after first promote: current=%q previous=%q", a.CurrentDraftID, a.PreviousDraftID)
	}
	if a.PromotedBy != "alice" {
		t.Fatalf("PromotedBy not captured, got %q", a.PromotedBy)
	}

	a, err = s.Promote(ctx, d2.ID, "bob", "")
	if err != nil {
		t.Fatalf("promote 2: %v", err)
	}
	if a.CurrentDraftID != d2.ID || a.PreviousDraftID != d1.ID {
		t.Fatalf("after second promote: current=%q previous=%q", a.CurrentDraftID, a.PreviousDraftID)
	}
}

func TestMemoryStore_PromoteSameDraftIsNoOp(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()
	d1, _ := s.CreateDraft(ctx, Draft{Name: "v1", RegoSource: validRego})

	first, err := s.Promote(ctx, d1.ID, "alice", "")
	if err != nil {
		t.Fatalf("promote 1: %v", err)
	}
	second, err := s.Promote(ctx, d1.ID, "alice-again", "")
	if err != nil {
		t.Fatalf("promote 2: %v", err)
	}
	if !second.PromotedAt.Equal(first.PromotedAt) {
		t.Fatal("re-promoting same draft should not refresh PromotedAt")
	}
	if second.PromotedBy != first.PromotedBy {
		t.Fatal("re-promoting same draft should not refresh PromotedBy")
	}
}

func TestMemoryStore_RollbackFlipsThenClears(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()
	d1, _ := s.CreateDraft(ctx, Draft{Name: "v1", RegoSource: validRego})
	d2, _ := s.CreateDraft(ctx, Draft{Name: "v2", RegoSource: validRego2})
	_, _ = s.Promote(ctx, d1.ID, "alice", "")
	_, _ = s.Promote(ctx, d2.ID, "bob", "")

	a, err := s.Rollback(ctx, "carol", "")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if a.CurrentDraftID != d1.ID {
		t.Fatalf("rollback should make d1 current, got %q", a.CurrentDraftID)
	}
	if a.PreviousDraftID != "" {
		t.Fatalf("rollback should clear previous to avoid ping-pong, got %q", a.PreviousDraftID)
	}

	// Second rollback has nothing to do.
	if _, err := s.Rollback(ctx, "carol", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second rollback should be ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_DeleteRejectsActive(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()
	d1, _ := s.CreateDraft(ctx, Draft{Name: "v1", RegoSource: validRego})
	d2, _ := s.CreateDraft(ctx, Draft{Name: "v2", RegoSource: validRego2})
	_, _ = s.Promote(ctx, d1.ID, "", "")
	_, _ = s.Promote(ctx, d2.ID, "", "")
	// After two promotes: d2 current, d1 previous. Both should be
	// undeletable.
	if err := s.DeleteDraft(ctx, d1.ID); !errors.Is(err, ErrActiveDraftDelete) {
		t.Fatalf("delete of previous active should be rejected, got %v", err)
	}
	if err := s.DeleteDraft(ctx, d2.ID); !errors.Is(err, ErrActiveDraftDelete) {
		t.Fatalf("delete of current active should be rejected, got %v", err)
	}

	// Create a fresh draft that isn't active; delete should work.
	d3, _ := s.CreateDraft(ctx, Draft{Name: "v3", RegoSource: validRego})
	if err := s.DeleteDraft(ctx, d3.ID); err != nil {
		t.Fatalf("delete of non-active draft should succeed, got %v", err)
	}
	if _, err := s.GetDraft(ctx, d3.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete, GetDraft should return ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_PromoteUnknownDraft(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	if _, err := s.Promote(context.Background(), "nope", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("promote nonexistent should be ErrNotFound, got %v", err)
	}
}

func TestActiveMarshalJSON_ElidesZeroPromotedAt(t *testing.T) {
	t.Parallel()
	// Zero-valued Active (fresh install, nothing promoted).
	b, err := json.Marshal(Active{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "0001-01-01") {
		t.Fatalf("zero-promoted_at leaked into JSON: %s", b)
	}
	if strings.Contains(string(b), "promoted_at") {
		t.Fatalf("expected promoted_at to be elided, got: %s", b)
	}
}

func TestActiveMarshalJSON_PreservesPromotedAtWhenSet(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 5, 11, 13, 19, 49, 0, time.UTC)
	b, err := json.Marshal(Active{
		CurrentDraftID: "abc123",
		PromotedAt:     when,
		PromotedBy:     "joe@laptop",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"promoted_at":"2026-05-11T13:19:49Z"`) {
		t.Fatalf("expected promoted_at preserved, got: %s", b)
	}
	if !strings.Contains(string(b), `"promoted_by":"joe@laptop"`) {
		t.Fatalf("expected promoted_by preserved, got: %s", b)
	}
}

func TestMemoryStore_WatchDeliversOnPromote(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	d, _ := s.CreateDraft(context.Background(), Draft{Name: "v1", RegoSource: validRego})
	_, err = s.Promote(context.Background(), d.ID, "alice", "")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	select {
	case got := <-ch:
		if got.CurrentDraftID != d.ID {
			t.Fatalf("delivered active.CurrentDraftID=%q, want %q", got.CurrentDraftID, d.ID)
		}
		if got.PromotedBy != "alice" {
			t.Fatalf("delivered PromotedBy=%q, want alice", got.PromotedBy)
		}
	case <-time.After(time.Second):
		t.Fatal("Watch did not deliver promotion within 1s")
	}
}

func TestMemoryStore_WatchDeliversOnRollback(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	d1, _ := s.CreateDraft(context.Background(), Draft{Name: "v1", RegoSource: validRego})
	d2, _ := s.CreateDraft(context.Background(), Draft{Name: "v2", RegoSource: validRego2})
	_, _ = s.Promote(context.Background(), d1.ID, "", "")
	_, _ = s.Promote(context.Background(), d2.ID, "", "")
	// Subscribe AFTER both promotes so we only see the rollback.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, _ := s.Watch(ctx)

	if _, err := s.Rollback(context.Background(), "alice", ""); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	select {
	case got := <-ch:
		if got.CurrentDraftID != d1.ID {
			t.Fatalf("after rollback delivered CurrentDraftID=%q, want %q", got.CurrentDraftID, d1.ID)
		}
		if got.PreviousDraftID != "" {
			t.Fatalf("rollback should clear previous, got %q", got.PreviousDraftID)
		}
	case <-time.After(time.Second):
		t.Fatal("Watch did not deliver rollback within 1s")
	}
}

func TestMemoryStore_WatchCtxCancelClosesChannel(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := s.Watch(ctx)
	cancel()
	// Give the unsubscribe goroutine a moment to run.
	deadline := time.After(time.Second)
	for {
		select {
		case _, open := <-ch:
			if !open {
				return // expected
			}
		case <-deadline:
			t.Fatal("Watch channel did not close after ctx cancel")
		}
	}
}

func TestMemoryStore_WatchMultipleSubscribers(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, _ := s.Watch(ctx)
	b, _ := s.Watch(ctx)
	c, _ := s.Watch(ctx)

	d, _ := s.CreateDraft(context.Background(), Draft{Name: "v1", RegoSource: validRego})
	_, _ = s.Promote(context.Background(), d.ID, "", "")

	for i, ch := range []<-chan Active{a, b, c} {
		select {
		case got := <-ch:
			if got.CurrentDraftID != d.ID {
				t.Fatalf("subscriber %d got %q, want %q", i, got.CurrentDraftID, d.ID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d did not receive within 1s", i)
		}
	}
}

func TestMemoryStore_WatchSlowConsumerDoesNotBlock(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Subscribe but never read. After we fill the buffer the next
	// promote should drop on send rather than block — verify by
	// timing: a bunch of promotes should complete promptly.
	_, _ = s.Watch(ctx)

	d, _ := s.CreateDraft(context.Background(), Draft{Name: "v1", RegoSource: validRego})

	done := make(chan struct{})
	go func() {
		// 20 promotes against the same draft is a no-op except for
		// the very first one (re-promote of same id is idempotent),
		// so we alternate to force a state change each time.
		d2, _ := s.CreateDraft(context.Background(), Draft{Name: "v2", RegoSource: validRego2})
		for i := 0; i < 20; i++ {
			target := d.ID
			if i%2 == 0 {
				target = d2.ID
			}
			_, _ = s.Promote(context.Background(), target, "", "")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow consumer blocked promote chain")
	}
}

func TestMemoryStore_UpdateKeepsTenantAndCreatedAt(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()
	d, _ := s.CreateDraft(ctx, Draft{
		Name:       "v1",
		RegoSource: validRego,
		Tenant:     "acme",
		CreatedBy:  "alice",
	})
	originalCreatedAt := d.CreatedAt
	originalTenant := d.Tenant

	updated, err := s.UpdateDraft(ctx, Draft{
		ID:          d.ID,
		Name:        "v1-renamed",
		Description: "now with a description",
		RegoSource:  validRego2,
		// Caller tries to sneak in a different tenant — store
		// preserves the stored value.
		Tenant: "evil",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Tenant != originalTenant {
		t.Fatalf("update changed tenant: %q want %q", updated.Tenant, originalTenant)
	}
	if !updated.CreatedAt.Equal(originalCreatedAt) {
		t.Fatal("update modified CreatedAt")
	}
	if !updated.UpdatedAt.After(originalCreatedAt) && !updated.UpdatedAt.Equal(originalCreatedAt) {
		t.Fatalf("UpdatedAt did not advance: %v", updated.UpdatedAt)
	}
	if updated.RegoSource != validRego2 {
		t.Fatal("update did not change rego_source")
	}
}

// --- Per-tenant active pointer tests (session 38) ---

// TestMemoryStore_PerTenantPromoteIsolation proves that promoting
// against tenant=acme leaves tenant=globex and the default-fallback
// slot untouched. This is the central correctness claim of the
// per-tenant active design — one tenant's policy change must not
// be visible from another tenant's active pointer.
func TestMemoryStore_PerTenantPromoteIsolation(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	acmeDraft, _ := s.CreateDraft(ctx, Draft{Name: "acme-v1", RegoSource: validRego, Tenant: "acme"})
	globexDraft, _ := s.CreateDraft(ctx, Draft{Name: "globex-v1", RegoSource: validRego2, Tenant: "globex"})

	if _, err := s.Promote(ctx, acmeDraft.ID, "acme-admin", "acme"); err != nil {
		t.Fatalf("promote acme: %v", err)
	}

	acmeActive, _ := s.GetActive(ctx, "acme")
	globexActive, _ := s.GetActive(ctx, "globex")
	defaultActive, _ := s.GetActive(ctx, "")

	if acmeActive.CurrentDraftID != acmeDraft.ID {
		t.Errorf("acme active should be acme draft, got %q", acmeActive.CurrentDraftID)
	}
	if acmeActive.Tenant != "acme" {
		t.Errorf("acme active should carry tenant=acme, got %q", acmeActive.Tenant)
	}
	if globexActive.CurrentDraftID != "" {
		t.Errorf("globex active should be empty after acme promote, got %q", globexActive.CurrentDraftID)
	}
	if defaultActive.CurrentDraftID != "" {
		t.Errorf("default active should be empty after acme promote, got %q", defaultActive.CurrentDraftID)
	}

	// Globex promotes its own — acme's row must remain untouched.
	if _, err := s.Promote(ctx, globexDraft.ID, "globex-admin", "globex"); err != nil {
		t.Fatalf("promote globex: %v", err)
	}
	acmeAfter, _ := s.GetActive(ctx, "acme")
	if acmeAfter.CurrentDraftID != acmeDraft.ID {
		t.Errorf("acme active changed after globex promote: %q (want %q)", acmeAfter.CurrentDraftID, acmeDraft.ID)
	}
	globexAfter, _ := s.GetActive(ctx, "globex")
	if globexAfter.CurrentDraftID != globexDraft.ID {
		t.Errorf("globex active wrong: %q (want %q)", globexAfter.CurrentDraftID, globexDraft.ID)
	}
}

// TestMemoryStore_PerTenantRollbackIsolation proves rollback only
// flips the named tenant's pointer.
func TestMemoryStore_PerTenantRollbackIsolation(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	a1, _ := s.CreateDraft(ctx, Draft{Name: "acme-v1", RegoSource: validRego, Tenant: "acme"})
	a2, _ := s.CreateDraft(ctx, Draft{Name: "acme-v2", RegoSource: validRego2, Tenant: "acme"})
	g1, _ := s.CreateDraft(ctx, Draft{Name: "globex-v1", RegoSource: validRego, Tenant: "globex"})

	_, _ = s.Promote(ctx, a1.ID, "", "acme")
	_, _ = s.Promote(ctx, a2.ID, "", "acme")
	_, _ = s.Promote(ctx, g1.ID, "", "globex")

	// Rollback acme — globex should be untouched.
	rb, err := s.Rollback(ctx, "alice", "acme")
	if err != nil {
		t.Fatalf("rollback acme: %v", err)
	}
	if rb.CurrentDraftID != a1.ID {
		t.Errorf("acme rollback current %q, want %q", rb.CurrentDraftID, a1.ID)
	}
	if rb.Tenant != "acme" {
		t.Errorf("rollback tenant = %q, want acme", rb.Tenant)
	}

	globexActive, _ := s.GetActive(ctx, "globex")
	if globexActive.CurrentDraftID != g1.ID {
		t.Errorf("globex active changed by acme rollback: %q (want %q)", globexActive.CurrentDraftID, g1.ID)
	}

	// Rollback with no previous (we cleared it on the rollback above)
	// returns ErrNotFound.
	if _, err := s.Rollback(ctx, "alice", "acme"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second acme rollback expected ErrNotFound, got %v", err)
	}
	// But globex still has nothing to roll back to either (only one promote there).
	if _, err := s.Rollback(ctx, "", "globex"); !errors.Is(err, ErrNotFound) {
		t.Errorf("globex single-promote rollback expected ErrNotFound, got %v", err)
	}
}

// TestMemoryStore_ListActiveOrdersDefaultFirst proves ListActive
// returns the default-fallback row before per-tenant overlays —
// startup hydration depends on this ordering so the fallback is
// installed before the per-tenant slots that might shadow it.
func TestMemoryStore_ListActiveOrdersDefaultFirst(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	def, _ := s.CreateDraft(ctx, Draft{Name: "default", RegoSource: validRego})
	g, _ := s.CreateDraft(ctx, Draft{Name: "globex-v1", RegoSource: validRego2, Tenant: "globex"})
	a, _ := s.CreateDraft(ctx, Draft{Name: "acme-v1", RegoSource: validRego, Tenant: "acme"})

	// Promote in a deliberately non-alphabetical order.
	_, _ = s.Promote(ctx, g.ID, "", "globex")
	_, _ = s.Promote(ctx, a.ID, "", "acme")
	_, _ = s.Promote(ctx, def.ID, "", "")

	rows, err := s.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 active rows, got %d", len(rows))
	}
	if rows[0].Tenant != "" {
		t.Errorf("first row should be default fallback (tenant=\"\"), got %q", rows[0].Tenant)
	}
	if rows[1].Tenant != "acme" {
		t.Errorf("second row should be acme (alphabetical), got %q", rows[1].Tenant)
	}
	if rows[2].Tenant != "globex" {
		t.Errorf("third row should be globex, got %q", rows[2].Tenant)
	}
}

// TestMemoryStore_DeleteActiveClearsTenantSlot proves DeleteActive
// removes the tenant's row entirely so a subsequent GetActive
// returns the zero-value Active. Other tenants' rows are unaffected.
func TestMemoryStore_DeleteActiveClearsTenantSlot(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	a, _ := s.CreateDraft(ctx, Draft{Name: "acme-v1", RegoSource: validRego, Tenant: "acme"})
	g, _ := s.CreateDraft(ctx, Draft{Name: "globex-v1", RegoSource: validRego2, Tenant: "globex"})
	_, _ = s.Promote(ctx, a.ID, "", "acme")
	_, _ = s.Promote(ctx, g.ID, "", "globex")

	cleared, err := s.DeleteActive(ctx, "acme")
	if err != nil {
		t.Fatalf("delete active: %v", err)
	}
	if cleared.CurrentDraftID != "" {
		t.Errorf("DeleteActive should return zero-value Active, got %+v", cleared)
	}
	if cleared.Tenant != "acme" {
		t.Errorf("DeleteActive return should carry the cleared tenant, got %q", cleared.Tenant)
	}

	// Acme's row is gone.
	acmeAfter, _ := s.GetActive(ctx, "acme")
	if acmeAfter.CurrentDraftID != "" {
		t.Errorf("acme active should be empty after DeleteActive, got %q", acmeAfter.CurrentDraftID)
	}

	// Globex's row survives.
	globexAfter, _ := s.GetActive(ctx, "globex")
	if globexAfter.CurrentDraftID != g.ID {
		t.Errorf("globex active changed by acme DeleteActive: %q (want %q)",
			globexAfter.CurrentDraftID, g.ID)
	}
}

// TestMemoryStore_DeleteActiveEmptyTenantIsNoOp proves the default-
// fallback slot is protected. Calling DeleteActive("") returns the
// row unchanged so the gateway always has SOMETHING to serve as
// the platform default.
func TestMemoryStore_DeleteActiveEmptyTenantIsNoOp(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	d, _ := s.CreateDraft(ctx, Draft{Name: "platform-default", RegoSource: validRego})
	_, _ = s.Promote(ctx, d.ID, "", "")

	before, _ := s.GetActive(ctx, "")
	cleared, err := s.DeleteActive(ctx, "")
	if err != nil {
		t.Fatalf("delete active empty: %v", err)
	}
	// Cleared mirrors the row that's still there.
	if cleared.CurrentDraftID != d.ID {
		t.Errorf("DeleteActive('') should return the unchanged default row, got %+v", cleared)
	}
	after, _ := s.GetActive(ctx, "")
	if after.CurrentDraftID != before.CurrentDraftID {
		t.Errorf("DeleteActive('') changed the default row: before=%q after=%q",
			before.CurrentDraftID, after.CurrentDraftID)
	}
}

// TestMemoryStore_DeleteActiveFansOutClearSignal proves the watch
// channel receives an Active with empty CurrentDraftID + the
// affected tenant — the cross-replica signal main.go's watcher
// uses to drop the tenant's reloader slot.
func TestMemoryStore_DeleteActiveFansOutClearSignal(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, _ := s.CreateDraft(context.Background(), Draft{Name: "v1", RegoSource: validRego, Tenant: "acme"})
	_, _ = s.Promote(context.Background(), d.ID, "", "acme")

	ch, _ := s.Watch(ctx)
	if _, err := s.DeleteActive(context.Background(), "acme"); err != nil {
		t.Fatalf("delete active: %v", err)
	}
	select {
	case got := <-ch:
		if got.Tenant != "acme" {
			t.Errorf("clear signal tenant = %q, want acme", got.Tenant)
		}
		if got.CurrentDraftID != "" {
			t.Errorf("clear signal should carry empty CurrentDraftID, got %q", got.CurrentDraftID)
		}
	case <-time.After(time.Second):
		t.Fatal("Watch did not deliver clear signal within 1s")
	}
}

// TestMemoryStore_DeleteRejectsCrossTenantActive proves the active-
// reference sweep covers EVERY tenant's pointer — a draft pinned
// as acme's previous can't be deleted via the globex admin path.
func TestMemoryStore_DeleteRejectsCrossTenantActive(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	ctx := context.Background()

	d, _ := s.CreateDraft(ctx, Draft{Name: "v1", RegoSource: validRego, Tenant: "acme"})
	_, _ = s.Promote(ctx, d.ID, "", "acme")

	// d is pinned as acme's current. Deleting it must fail regardless
	// of how the caller is "labeled" — DeleteDraft is per-id, not
	// per-tenant.
	if err := s.DeleteDraft(ctx, d.ID); !errors.Is(err, ErrActiveDraftDelete) {
		t.Fatalf("delete should be rejected, got %v", err)
	}
}
