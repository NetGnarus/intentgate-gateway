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
