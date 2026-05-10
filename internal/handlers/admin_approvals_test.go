package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/approvals"
)

func newApprovalsHandler(t *testing.T) (http.Handler, http.Handler, approvals.Store) {
	t.Helper()
	store := approvals.NewMemoryStore()
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		Approvals:  store,
	}
	// Wrap the decide handler in a mux so r.PathValue("id") resolves
	// through the {id} pattern the way the real server does.
	mux := http.NewServeMux()
	mux.Handle("POST /v1/admin/approvals/{id}/decide", NewAdminApprovalsDecideHandler(cfg))
	return NewAdminApprovalsListHandler(cfg), mux, store
}

func TestAdminApprovals_ListAuthAndShape(t *testing.T) {
	listH, _, store := newApprovalsHandler(t)
	_, _ = store.Enqueue(context.Background(), approvals.PendingRequest{
		AgentID: "agent-x", Tool: "transfer_funds", Reason: "above 1000",
	})

	t.Run("no token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		listH.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/admin/approvals", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", rr.Code)
		}
	})
	t.Run("returns pending list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/approvals", nil)
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		listH.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		var resp struct {
			Approvals []approvals.PendingRequest `json:"approvals"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Approvals) != 1 {
			t.Errorf("want 1 row, got %d", len(resp.Approvals))
		}
	})
}

func TestAdminApprovals_DecideAcceptsApprove(t *testing.T) {
	_, decideMux, store := newApprovalsHandler(t)
	row, _ := store.Enqueue(context.Background(), approvals.PendingRequest{
		AgentID: "agent-x", Tool: "transfer_funds",
	})

	body := `{"decision":"approve","decided_by":"alice@acme","note":"reviewed"}`
	req := httptest.NewRequest(http.MethodPost,
		"/v1/admin/approvals/"+row.PendingID+"/decide", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	decideMux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var got approvals.PendingRequest
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != approvals.StatusApproved || got.DecidedBy != "alice@acme" {
		t.Errorf("decided row = %+v", got)
	}
}

func TestAdminApprovals_DoubleDecideReturns409(t *testing.T) {
	_, decideMux, store := newApprovalsHandler(t)
	row, _ := store.Enqueue(context.Background(), approvals.PendingRequest{
		AgentID: "agent-x", Tool: "transfer_funds",
	})
	if _, err := store.Decide(context.Background(), row.PendingID,
		approvals.Decision{Status: approvals.StatusApproved, DecidedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	body := `{"decision":"reject"}`
	req := httptest.NewRequest(http.MethodPost,
		"/v1/admin/approvals/"+row.PendingID+"/decide", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	decideMux.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", rr.Code)
	}
}

func TestAdminApprovals_DecideUnknownReturns404(t *testing.T) {
	_, decideMux, _ := newApprovalsHandler(t)
	body := `{"decision":"approve"}`
	req := httptest.NewRequest(http.MethodPost,
		"/v1/admin/approvals/does-not-exist/decide", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	decideMux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestAdminApprovals_PerTenantScoping(t *testing.T) {
	store := approvals.NewMemoryStore()
	cfg := AdminConfig{
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:   "super",
		TenantAdmins: map[string]string{"acme": "tok-acme", "globex": "tok-globex"},
		Approvals:    store,
	}
	listH := NewAdminApprovalsListHandler(cfg)
	mux := http.NewServeMux()
	mux.Handle("POST /v1/admin/approvals/{id}/decide", NewAdminApprovalsDecideHandler(cfg))

	// Seed: one row in acme, one in globex.
	rowA, _ := store.Enqueue(context.Background(), approvals.PendingRequest{
		AgentID: "agent-a", Tool: "x", Tenant: "acme",
	})
	rowG, _ := store.Enqueue(context.Background(), approvals.PendingRequest{
		AgentID: "agent-g", Tool: "y", Tenant: "globex",
	})

	get := func(t *testing.T, token string) []approvals.PendingRequest {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/approvals", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		listH.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list: status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Approvals []approvals.PendingRequest `json:"approvals"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp.Approvals
	}

	t.Run("acme admin sees only acme rows", func(t *testing.T) {
		got := get(t, "tok-acme")
		if len(got) != 1 || got[0].PendingID != rowA.PendingID {
			t.Errorf("acme list = %+v want [rowA]", got)
		}
	})
	t.Run("globex admin sees only globex rows", func(t *testing.T) {
		got := get(t, "tok-globex")
		if len(got) != 1 || got[0].PendingID != rowG.PendingID {
			t.Errorf("globex list = %+v want [rowG]", got)
		}
	})
	t.Run("superadmin sees both", func(t *testing.T) {
		got := get(t, "super")
		if len(got) != 2 {
			t.Errorf("super list len=%d want 2", len(got))
		}
	})

	t.Run("acme admin cannot decide globex row (404)", func(t *testing.T) {
		body := `{"decision":"approve"}`
		req := httptest.NewRequest(http.MethodPost,
			"/v1/admin/approvals/"+rowG.PendingID+"/decide", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok-acme")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("cross-tenant decide: status=%d want 404", rr.Code)
		}
	})
	t.Run("acme admin can decide own row", func(t *testing.T) {
		body := `{"decision":"approve","decided_by":"alice"}`
		req := httptest.NewRequest(http.MethodPost,
			"/v1/admin/approvals/"+rowA.PendingID+"/decide", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok-acme")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("same-tenant decide: status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestAdminApprovals_DecideRejectsBadDecision(t *testing.T) {
	_, decideMux, store := newApprovalsHandler(t)
	row, _ := store.Enqueue(context.Background(), approvals.PendingRequest{
		AgentID: "agent-x", Tool: "transfer_funds",
	})
	body := `{"decision":"maybe"}`
	req := httptest.NewRequest(http.MethodPost,
		"/v1/admin/approvals/"+row.PendingID+"/decide", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	decideMux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}
