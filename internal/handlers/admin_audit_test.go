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

// freshStore returns a memory store seeded with a deterministic mix of
// events for filter testing.
func freshStore(t *testing.T) auditstore.Store {
	t.Helper()
	s := auditstore.NewMemoryStore(100)
	now := time.Now().UTC()

	make := func(d time.Duration, decision audit.Decision, tool, agent string) audit.Event {
		e := audit.NewEvent(decision, tool)
		e.Timestamp = now.Add(d).Format(time.RFC3339Nano)
		e.AgentID = agent
		return e
	}

	for _, e := range []audit.Event{
		make(0, audit.DecisionAllow, "read_invoice", "agent-a"),
		make(time.Second, audit.DecisionBlock, "send_email", "agent-b"),
		make(2*time.Second, audit.DecisionAllow, "send_email", "agent-a"),
		make(3*time.Second, audit.DecisionAllow, "read_invoice", "agent-b"),
		make(4*time.Second, audit.DecisionBlock, "delete_record", "agent-a"),
	} {
		if err := s.Insert(context.Background(), e); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
	return s
}

func newAuditQueryRequest(t *testing.T, query, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func decodeAuditResp(t *testing.T, body io.Reader) (events []audit.Event, total int64, hasTotal bool) {
	t.Helper()
	var raw struct {
		Events []audit.Event `json:"events"`
		Total  *int64        `json:"total"`
	}
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if raw.Total != nil {
		return raw.Events, *raw.Total, true
	}
	return raw.Events, 0, false
}

func TestAdminAuditQuery_Auth(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshStore(t),
	}
	h := NewAdminAuditQueryHandler(cfg)

	t.Run("no token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newAuditQueryRequest(t, "", ""))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", rr.Code)
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newAuditQueryRequest(t, "", "nope"))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", rr.Code)
		}
	})
	t.Run("right token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newAuditQueryRequest(t, "", "secret"))
		if rr.Code != http.StatusOK {
			t.Errorf("want 200, got %d", rr.Code)
		}
	})
}

func TestAdminAuditQuery_NoStoreReturns503(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: nil,
	}
	h := NewAdminAuditQueryHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newAuditQueryRequest(t, "", "secret"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", rr.Code)
	}
}

func TestAdminAuditQuery_Filters(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshStore(t),
	}
	h := NewAdminAuditQueryHandler(cfg)

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"all", "", 5},
		{"agent-a", "agent_id=agent-a", 3},
		{"send_email", "tool=send_email", 2},
		{"blocks only", "decision=block", 2},
		{"compound", "tool=send_email&decision=allow", 1},
		{"no match", "agent_id=nope", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, newAuditQueryRequest(t, tc.query, "secret"))
			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d (body=%s)", rr.Code, rr.Body.String())
			}
			events, _, _ := decodeAuditResp(t, rr.Body)
			if len(events) != tc.want {
				t.Errorf("want %d events, got %d (body=%s)", tc.want, len(events), rr.Body.String())
			}
		})
	}
}

func TestAdminAuditQuery_BadFromTo(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshStore(t),
	}
	h := NewAdminAuditQueryHandler(cfg)
	for _, q := range []string{"from=not-a-date", "to=also-bad"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newAuditQueryRequest(t, q, "secret"))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("query %q: want 400, got %d", q, rr.Code)
		}
	}
}

func TestAdminAuditQuery_LimitOffsetClamped(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshStore(t),
	}
	h := NewAdminAuditQueryHandler(cfg)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newAuditQueryRequest(t, "limit=2", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	events, _, _ := decodeAuditResp(t, rr.Body)
	if len(events) != 2 {
		t.Errorf("want 2 events with limit=2, got %d", len(events))
	}

	// limit > 1000 silently clamps in the store.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, newAuditQueryRequest(t, "limit=99999", "secret"))
	if rr2.Code != http.StatusOK {
		t.Fatalf("want 200 on huge limit, got %d", rr2.Code)
	}
}

func TestAdminAuditQuery_CountOptIn(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshStore(t),
	}
	h := NewAdminAuditQueryHandler(cfg)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newAuditQueryRequest(t, "count=true&decision=allow", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	_, total, has := decodeAuditResp(t, rr.Body)
	if !has {
		t.Fatal("expected total in response when count=true")
	}
	if total != 3 {
		t.Errorf("want total=3 allows, got %d", total)
	}
}
