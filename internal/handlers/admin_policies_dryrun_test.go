package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
)

const dryRunRego = `package intentgate.policy
import rego.v1

default decision := {"allow": true, "reason": "default-allow"}

decision := {"allow": false, "reason": "transfer_funds blocked"} if {
	input.tool == "transfer_funds"
}
`

func TestAdminPoliciesDryRunHappyPath(t *testing.T) {
	t.Parallel()

	store := auditstore.NewMemoryStore(100)
	mustInsert(t, store, mkEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot", audit.DecisionAllow))
	mustInsert(t, store, mkEvent("2026-05-10T10:00:01Z", "read_invoice", "fin-bot", audit.DecisionAllow))

	cfg := AdminConfig{
		AdminToken: "super",
		AuditStore: store,
	}
	h := NewAdminPoliciesDryRunHandler(cfg)

	body := mustJSON(t, map[string]any{"rego": dryRunRego})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer super")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Summary struct {
			EventsEvaluated int `json:"events_evaluated"`
			CandidateBlock  int `json:"would_block"`
			AllowToBlock    int `json:"allow_to_block"`
		} `json:"summary"`
		Samples []map[string]any `json:"samples"`
		Window  struct {
			Tenant string `json:"tenant"`
			Limit  int    `json:"limit"`
		} `json:"window"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if resp.Summary.EventsEvaluated != 2 {
		t.Errorf("events_evaluated = %d, want 2", resp.Summary.EventsEvaluated)
	}
	if resp.Summary.CandidateBlock != 1 || resp.Summary.AllowToBlock != 1 {
		t.Errorf("summary = %+v, want would_block=1 allow_to_block=1", resp.Summary)
	}
	if len(resp.Samples) != 1 {
		t.Errorf("samples len = %d, want 1", len(resp.Samples))
	}
}

func TestAdminPoliciesDryRunRejectsUnauth(t *testing.T) {
	t.Parallel()
	store := auditstore.NewMemoryStore(10)
	h := NewAdminPoliciesDryRunHandler(AdminConfig{AdminToken: "super", AuditStore: store})

	body := mustJSON(t, map[string]any{"rego": dryRunRego})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	// Missing Authorization header.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAdminPoliciesDryRunRejectsBadRego(t *testing.T) {
	t.Parallel()
	store := auditstore.NewMemoryStore(10)
	h := NewAdminPoliciesDryRunHandler(AdminConfig{AdminToken: "super", AuditStore: store})

	body := mustJSON(t, map[string]any{"rego": "this is not valid rego"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer super")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for compile error; body=%s", w.Code, w.Body.String())
	}
}

func TestAdminPoliciesDryRunMissingRegoIs400(t *testing.T) {
	t.Parallel()
	store := auditstore.NewMemoryStore(10)
	h := NewAdminPoliciesDryRunHandler(AdminConfig{AdminToken: "super", AuditStore: store})

	body := mustJSON(t, map[string]any{})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer super")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "rego") {
		t.Errorf("body should mention 'rego', got %s", w.Body.String())
	}
}

func TestAdminPoliciesDryRunRejectsNoAuditStore(t *testing.T) {
	t.Parallel()
	h := NewAdminPoliciesDryRunHandler(AdminConfig{AdminToken: "super"})
	body := mustJSON(t, map[string]any{"rego": dryRunRego})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer super")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no audit store", w.Code)
	}
	if !strings.Contains(w.Body.String(), "INTENTGATE_AUDIT_PERSIST") {
		t.Errorf("body should mention env-var hint, got %s", w.Body.String())
	}
}

func TestAdminPoliciesDryRunTenantScoping(t *testing.T) {
	t.Parallel()
	store := auditstore.NewMemoryStore(10)
	// One event under each tenant.
	acmeEv := mkEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot", audit.DecisionAllow)
	acmeEv.Tenant = "acme"
	globexEv := mkEvent("2026-05-10T10:00:01Z", "transfer_funds", "ops-bot", audit.DecisionAllow)
	globexEv.Tenant = "globex"
	mustInsert(t, store, acmeEv)
	mustInsert(t, store, globexEv)

	cfg := AdminConfig{
		TenantAdmins: map[string]string{"acme": "tok-acme"},
		AuditStore:   store,
	}
	h := NewAdminPoliciesDryRunHandler(cfg)

	// acme admin → sees only acme's event.
	body := mustJSON(t, map[string]any{"rego": dryRunRego})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-acme")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("acme status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Summary struct {
			EventsEvaluated int `json:"events_evaluated"`
		} `json:"summary"`
		Window struct {
			Tenant string `json:"tenant"`
		} `json:"window"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Summary.EventsEvaluated != 1 || resp.Window.Tenant != "acme" {
		t.Errorf("acme isolation broken: events=%d tenant=%q",
			resp.Summary.EventsEvaluated, resp.Window.Tenant)
	}

	// acme admin trying to pass tenant=globex → 403.
	body = mustJSON(t, map[string]any{"rego": dryRunRego, "tenant": "globex"})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/policies/dry-run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-acme")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant attempt status = %d, want 403", w.Code)
	}
}

func mkEvent(ts, tool, agent string, dec audit.Decision) audit.Event {
	return audit.Event{
		Timestamp:     ts,
		EventName:     "intentgate.tool_call",
		SchemaVersion: "3",
		Decision:      dec,
		Tool:          tool,
		AgentID:       agent,
		Tenant:        "default",
	}
}

func mustInsert(t *testing.T, s *auditstore.MemoryStore, e audit.Event) {
	t.Helper()
	if err := s.Insert(context.Background(), e); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
