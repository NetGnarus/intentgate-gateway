package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
)

// freshChainStore seeds a memory store with a few chained events on
// tenant 'acme' so the verify endpoint has a non-zero chain to walk
// and head telemetry to surface.
func freshChainStore(t *testing.T) auditstore.Store {
	t.Helper()
	s := auditstore.NewMemoryStore(100)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		e := audit.NewEvent(audit.DecisionAllow, "read")
		e.Timestamp = now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		e.Tenant = "acme"
		if err := s.Insert(context.Background(), e); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return s
}

func newVerifyRequest(t *testing.T, query, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit/verify?"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// Verify response MUST include head_at (RFC3339) and head_id (int64)
// when the per-tenant chain has at least one event. Console-pro reads
// these to render "chain last advanced N seconds ago" on /audit/verify.
func TestAdminAuditVerify_SurfacesHeadTelemetry(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshChainStore(t),
	}
	h := NewAdminAuditVerifyHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newVerifyRequest(t, "tenant=acme", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		OK       bool   `json:"ok"`
		Verified int    `json:"verified"`
		HeadAt   string `json:"head_at"`
		HeadID   int64  `json:"head_id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK {
		t.Errorf("want OK=true, got %+v", resp)
	}
	if resp.HeadAt == "" {
		t.Errorf("head_at missing from response: %s", rr.Body.String())
	}
	if resp.HeadID == 0 {
		t.Errorf("head_id missing or zero: %s", rr.Body.String())
	}
	// Confirm head_at parses as RFC3339Nano.
	if _, err := time.Parse(time.RFC3339Nano, resp.HeadAt); err != nil {
		t.Errorf("head_at not RFC3339Nano: %v (raw=%q)", err, resp.HeadAt)
	}
}

// A tenant with no events MUST omit head_at + head_id entirely so
// console-pro can render a "no events yet" hint instead of a
// 56-years-ago timestamp.
func TestAdminAuditVerify_EmptyTenantOmitsHeadFields(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: auditstore.NewMemoryStore(100),
	}
	h := NewAdminAuditVerifyHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newVerifyRequest(t, "tenant=ghost", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	// Decode into a map so we can assert key absence (not just zero
	// values).
	var raw map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["head_at"]; ok {
		t.Errorf("head_at present on empty tenant: %v", raw)
	}
	if _, ok := raw["head_id"]; ok {
		t.Errorf("head_id present on empty tenant: %v", raw)
	}
}
