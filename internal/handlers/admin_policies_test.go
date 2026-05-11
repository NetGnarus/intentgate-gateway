package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/policystore"
)

const policyTestRego = `package intentgate.policy
import rego.v1
default decision := {"allow": true, "reason": "test-default"}
`

const policyTestRegoV2 = `package intentgate.policy
import rego.v1
default decision := {"allow": false, "reason": "test-v2"}
`

// newPolicyAdminCfg builds a PolicyAdminConfig wired against an
// in-process MemoryStore and a fresh Reloader. Returned so tests
// can poke at the store / reloader directly when they need to
// verify side-effects.
func newPolicyAdminCfg(t *testing.T) (PolicyAdminConfig, *policystore.MemoryStore, *policy.Reloader) {
	t.Helper()
	store := policystore.NewMemoryStore()
	engine, err := policy.NewEngine(context.Background(), policyTestRego)
	if err != nil {
		t.Fatalf("seed engine: %v", err)
	}
	reloader := policy.NewReloader(engine)
	return PolicyAdminConfig{
		AdminToken: "super",
		TenantAdmins: map[string]string{
			"acme":   "acme-tok",
			"globex": "globex-tok",
		},
		Store:    store,
		Reloader: reloader,
		Audit:    audit.NewNullEmitter(),
	}, store, reloader
}

// doReq is a tiny helper to issue an authenticated admin request
// to a handler and unmarshal the response body into v (or pass nil
// to ignore the body).
func doReq(t *testing.T, h http.Handler, method, target, token string, body any, v any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if v != nil && w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
			t.Fatalf("unmarshal response: %v; body=%s", err, w.Body.String())
		}
	}
	return w
}

func TestPolicyDrafts_CreateRejectsBadRego(t *testing.T) {
	t.Parallel()
	cfg, _, _ := newPolicyAdminCfg(t)
	h := NewAdminDraftsCreateHandler(cfg)

	w := doReq(t, h, http.MethodPost, "/v1/admin/policies/drafts", "super",
		map[string]any{"rego_source": "this isn't rego at all"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rego compile error") {
		t.Errorf("body missing compile-error indicator: %s", w.Body.String())
	}
}

func TestPolicyDrafts_CreateHappy(t *testing.T) {
	t.Parallel()
	cfg, store, _ := newPolicyAdminCfg(t)
	h := NewAdminDraftsCreateHandler(cfg)

	var resp policystore.Draft
	w := doReq(t, h, http.MethodPost, "/v1/admin/policies/drafts", "super",
		map[string]any{
			"name":        "first",
			"description": "a starter policy",
			"rego_source": policyTestRego,
			"created_by":  "alice",
		}, &resp)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	if resp.ID == "" {
		t.Fatal("response missing draft ID")
	}
	if resp.Name != "first" || resp.CreatedBy != "alice" {
		t.Fatalf("response fields not populated: %+v", resp)
	}
	// Round-trip via the store directly.
	stored, err := store.GetDraft(context.Background(), resp.ID)
	if err != nil {
		t.Fatalf("store get: %v", err)
	}
	if stored.Tenant != "" {
		t.Errorf("superadmin-created draft should have empty tenant, got %q", stored.Tenant)
	}
}

func TestPolicyDrafts_TenantScopedCreate(t *testing.T) {
	t.Parallel()
	cfg, store, _ := newPolicyAdminCfg(t)
	h := NewAdminDraftsCreateHandler(cfg)

	// Per-tenant admin sneaks in a different tenant. Handler
	// returns 403, store has no row.
	w := doReq(t, h, http.MethodPost, "/v1/admin/policies/drafts", "acme-tok",
		map[string]any{
			"tenant":      "globex",
			"rego_source": policyTestRego,
		}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create: status = %d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Per-tenant admin with no tenant in body — gets stamped with
	// their tenant.
	var resp policystore.Draft
	w = doReq(t, h, http.MethodPost, "/v1/admin/policies/drafts", "acme-tok",
		map[string]any{"rego_source": policyTestRego}, &resp)
	if w.Code != http.StatusCreated {
		t.Fatalf("acme self-create: status = %d, want 201", w.Code)
	}
	stored, _ := store.GetDraft(context.Background(), resp.ID)
	if stored.Tenant != "acme" {
		t.Errorf("acme draft should be stamped tenant=acme, got %q", stored.Tenant)
	}
}

func TestPolicyDrafts_ListCrossTenantHidden(t *testing.T) {
	t.Parallel()
	cfg, store, _ := newPolicyAdminCfg(t)
	ctx := context.Background()
	_, _ = store.CreateDraft(ctx, policystore.Draft{Name: "a1", RegoSource: policyTestRego, Tenant: "acme"})
	_, _ = store.CreateDraft(ctx, policystore.Draft{Name: "g1", RegoSource: policyTestRego, Tenant: "globex"})
	_, _ = store.CreateDraft(ctx, policystore.Draft{Name: "s1", RegoSource: policyTestRego, Tenant: ""})

	h := NewAdminDraftsListHandler(cfg)

	// Superadmin sees all.
	var super struct {
		Drafts []policystore.Draft `json:"drafts"`
	}
	w := doReq(t, h, http.MethodGet, "/v1/admin/policies/drafts", "super", nil, &super)
	if w.Code != http.StatusOK {
		t.Fatalf("super list: %d", w.Code)
	}
	if len(super.Drafts) != 3 {
		t.Errorf("super should see 3 drafts, got %d", len(super.Drafts))
	}

	// Acme sees one.
	var acme struct {
		Drafts []policystore.Draft `json:"drafts"`
	}
	w = doReq(t, h, http.MethodGet, "/v1/admin/policies/drafts", "acme-tok", nil, &acme)
	if w.Code != http.StatusOK {
		t.Fatalf("acme list: %d", w.Code)
	}
	if len(acme.Drafts) != 1 || acme.Drafts[0].Tenant != "acme" {
		t.Errorf("acme list wrong: %+v", acme.Drafts)
	}
}

func TestPolicyDrafts_DeleteUnauth(t *testing.T) {
	t.Parallel()
	cfg, _, _ := newPolicyAdminCfg(t)
	mux := http.NewServeMux()
	mux.Handle("DELETE /v1/admin/policies/drafts/{id}", NewAdminDraftDeleteHandler(cfg))

	w := doReq(t, mux, http.MethodDelete, "/v1/admin/policies/drafts/anything", "", nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth delete: status = %d, want 401", w.Code)
	}
}

func TestPolicyDrafts_DeleteActiveRejected(t *testing.T) {
	t.Parallel()
	cfg, store, _ := newPolicyAdminCfg(t)
	ctx := context.Background()
	d, _ := store.CreateDraft(ctx, policystore.Draft{Name: "live", RegoSource: policyTestRego})
	_, _ = store.Promote(ctx, d.ID, "alice")

	mux := http.NewServeMux()
	mux.Handle("DELETE /v1/admin/policies/drafts/{id}", NewAdminDraftDeleteHandler(cfg))
	w := doReq(t, mux, http.MethodDelete, "/v1/admin/policies/drafts/"+d.ID, "super", nil, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("delete-active: status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func TestPolicyPromote_RequiresSuperadmin(t *testing.T) {
	t.Parallel()
	cfg, store, _ := newPolicyAdminCfg(t)
	d, _ := store.CreateDraft(context.Background(), policystore.Draft{
		Name: "v1", RegoSource: policyTestRego, Tenant: "acme",
	})
	h := NewAdminPromoteHandler(cfg)

	// Per-tenant admin tries to promote — 403.
	w := doReq(t, h, http.MethodPost, "/v1/admin/policies/active", "acme-tok",
		map[string]any{"draft_id": d.ID}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("per-tenant promote: status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestPolicyPromote_SwapsLiveEngine(t *testing.T) {
	t.Parallel()
	cfg, store, reloader := newPolicyAdminCfg(t)
	d, _ := store.CreateDraft(context.Background(), policystore.Draft{
		Name: "v2", RegoSource: policyTestRegoV2,
	})

	// Before promote: the live engine should evaluate the seeded
	// "test-default" policy (allow=true). After promote: the v2
	// policy is live (allow=false).
	pre, err := reloader.Current().Evaluate(context.Background(), map[string]any{"tool": "x"})
	if err != nil {
		t.Fatalf("pre-evaluate: %v", err)
	}
	if !pre.Allow {
		t.Fatal("expected seeded policy to allow")
	}

	h := NewAdminPromoteHandler(cfg)
	w := doReq(t, h, http.MethodPost, "/v1/admin/policies/active", "super",
		map[string]any{"draft_id": d.ID, "promoted_by": "alice"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("promote: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	post, err := reloader.Current().Evaluate(context.Background(), map[string]any{"tool": "x"})
	if err != nil {
		t.Fatalf("post-evaluate: %v", err)
	}
	if post.Allow {
		t.Fatal("expected promoted v2 policy to deny")
	}
}

func TestPolicyRollback_404WhenNothingToRevert(t *testing.T) {
	t.Parallel()
	cfg, _, _ := newPolicyAdminCfg(t)
	h := NewAdminRollbackHandler(cfg)
	w := doReq(t, h, http.MethodPost, "/v1/admin/policies/rollback", "super", map[string]any{}, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("rollback-empty: status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestPolicyRollback_RestoresPrevious(t *testing.T) {
	t.Parallel()
	cfg, store, reloader := newPolicyAdminCfg(t)
	d1, _ := store.CreateDraft(context.Background(), policystore.Draft{Name: "v1", RegoSource: policyTestRego})
	d2, _ := store.CreateDraft(context.Background(), policystore.Draft{Name: "v2", RegoSource: policyTestRegoV2})
	_, _ = store.Promote(context.Background(), d1.ID, "")
	// Promote v2 via the handler so the live engine sees v2.
	promoteH := NewAdminPromoteHandler(cfg)
	w := doReq(t, promoteH, http.MethodPost, "/v1/admin/policies/active", "super",
		map[string]any{"draft_id": d2.ID}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("seed promote: status = %d", w.Code)
	}

	// Confirm v2 live.
	mid, _ := reloader.Current().Evaluate(context.Background(), map[string]any{"tool": "x"})
	if mid.Allow {
		t.Fatal("expected v2 deny before rollback")
	}

	rollbackH := NewAdminRollbackHandler(cfg)
	w = doReq(t, rollbackH, http.MethodPost, "/v1/admin/policies/rollback", "super",
		map[string]any{"rolled_back_by": "alice"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback: status = %d; body=%s", w.Code, w.Body.String())
	}

	// v1 live again.
	post, _ := reloader.Current().Evaluate(context.Background(), map[string]any{"tool": "x"})
	if !post.Allow {
		t.Fatal("expected v1 allow after rollback")
	}

	// And the store-level pointer matches.
	active, _ := store.GetActive(context.Background())
	if active.CurrentDraftID != d1.ID || active.PreviousDraftID != "" {
		t.Fatalf("after rollback: current=%q previous=%q want d1=%q previous=empty",
			active.CurrentDraftID, active.PreviousDraftID, d1.ID)
	}
}

func TestPolicyActive_Source(t *testing.T) {
	t.Parallel()
	cfg, _, _ := newPolicyAdminCfg(t)
	h := NewAdminActiveGetHandler(cfg, "embedded")
	var resp struct {
		Source string `json:"source"`
		Active struct {
			CurrentDraftID string `json:"current_draft_id"`
		} `json:"active"`
	}
	w := doReq(t, h, http.MethodGet, "/v1/admin/policies/active", "super", nil, &resp)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if resp.Source != "embedded" {
		t.Errorf("source = %q, want embedded", resp.Source)
	}
	if resp.Active.CurrentDraftID != "" {
		t.Errorf("active current_draft_id = %q, want empty", resp.Active.CurrentDraftID)
	}
}
