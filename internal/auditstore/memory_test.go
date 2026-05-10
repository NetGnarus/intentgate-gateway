package auditstore

import (
	"context"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

func newTestEvent(t time.Time, decision audit.Decision, tool, agent string) audit.Event {
	e := audit.NewEvent(decision, tool)
	e.Timestamp = t.UTC().Format(time.RFC3339Nano)
	e.AgentID = agent
	return e
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0) // default capacity
	if s.cap != DefaultMemoryCapacity {
		t.Fatalf("default capacity not applied: %d", s.cap)
	}

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		e := newTestEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "read_invoice", "agent-a")
		if err := s.Insert(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	out, err := s.Query(ctx, QueryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(out) != 5 {
		t.Fatalf("want 5 events, got %d", len(out))
	}
	// Most-recent first.
	for i := 1; i < len(out); i++ {
		if out[i-1].Timestamp < out[i].Timestamp {
			t.Errorf("not sorted descending at index %d", i)
		}
	}
}

func TestMemoryStoreRoundTripsArgValues(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10)

	e := newTestEvent(time.Now().UTC(), audit.DecisionAllow, "transfer_funds", "fin-bot")
	e.ArgKeys = []string{"amount_eur", "recipient"}
	e.ArgValues = map[string]any{
		"amount_eur": 1500,
		"recipient":  nil, // string redacted by RedactScalars
	}
	if err := s.Insert(ctx, e); err != nil {
		t.Fatalf("insert: %v", err)
	}

	out, err := s.Query(ctx, QueryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 event, got %d", len(out))
	}
	if out[0].ArgValues["amount_eur"] != 1500 {
		t.Errorf("ArgValues[amount_eur] = %v, want 1500", out[0].ArgValues["amount_eur"])
	}
	if out[0].ArgValues["recipient"] != nil {
		t.Errorf("ArgValues[recipient] = %v, want nil", out[0].ArgValues["recipient"])
	}
}

func TestMemoryStoreFilters(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(100)
	now := time.Now().UTC()

	must := func(e audit.Event) {
		if err := s.Insert(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	must(newTestEvent(now, audit.DecisionAllow, "read_invoice", "agent-a"))
	must(newTestEvent(now.Add(time.Second), audit.DecisionBlock, "send_email", "agent-b"))
	must(newTestEvent(now.Add(2*time.Second), audit.DecisionAllow, "send_email", "agent-a"))

	cases := []struct {
		name string
		f    QueryFilter
		want int
	}{
		{"all", QueryFilter{}, 3},
		{"agent-a", QueryFilter{AgentID: "agent-a"}, 2},
		{"agent-b", QueryFilter{AgentID: "agent-b"}, 1},
		{"tool send_email", QueryFilter{Tool: "send_email"}, 2},
		{"decision block", QueryFilter{Decision: "block"}, 1},
		{"compound", QueryFilter{Tool: "send_email", Decision: "allow"}, 1},
		{"window from", QueryFilter{From: now.Add(time.Second)}, 2},
		{"window to", QueryFilter{To: now.Add(time.Second)}, 2},
		{"window narrow", QueryFilter{From: now.Add(time.Second), To: now.Add(time.Second)}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Query(ctx, tc.f)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("want %d events, got %d", tc.want, len(got))
			}
		})
	}
}

func TestMemoryStoreLimitAndOffset(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(20)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		_ = s.Insert(ctx, newTestEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "x", "a"))
	}

	out, err := s.Query(ctx, QueryFilter{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3, got %d", len(out))
	}

	out2, err := s.Query(ctx, QueryFilter{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(out2) != 3 {
		t.Fatalf("want 3, got %d", len(out2))
	}
	if out[0].Timestamp == out2[0].Timestamp {
		t.Errorf("offset did not advance the page")
	}
}

func TestMemoryStoreRingOverflow(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(3)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		_ = s.Insert(ctx, newTestEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "x", "a"))
	}
	out, err := s.Query(ctx, QueryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("ring did not bound: got %d", len(out))
	}
}

func TestMemoryStoreFiltersByTenant(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(100)
	now := time.Now().UTC()

	mk := func(tenant string) audit.Event {
		e := newTestEvent(now, audit.DecisionAllow, "x", "agent")
		e.Tenant = tenant
		return e
	}
	for i := 0; i < 3; i++ {
		_ = s.Insert(ctx, mk("acme"))
	}
	for i := 0; i < 2; i++ {
		_ = s.Insert(ctx, mk("globex"))
	}
	_ = s.Insert(ctx, mk("default"))

	out, err := s.Query(ctx, QueryFilter{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Errorf("want 3 acme rows, got %d", len(out))
	}
	all, _ := s.Query(ctx, QueryFilter{})
	if len(all) != 6 {
		t.Errorf("unfiltered want 6, got %d", len(all))
	}
}

func TestMemoryStoreCount(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10)
	now := time.Now().UTC()
	for i := 0; i < 7; i++ {
		_ = s.Insert(ctx, newTestEvent(now.Add(time.Duration(i)*time.Second), audit.DecisionAllow, "x", "a"))
	}
	for i := 0; i < 3; i++ {
		_ = s.Insert(ctx, newTestEvent(now.Add(time.Duration(i+10)*time.Second), audit.DecisionBlock, "x", "a"))
	}
	n, err := s.Count(ctx, QueryFilter{Decision: "block"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Errorf("want 3 blocks, got %d", n)
	}
}
