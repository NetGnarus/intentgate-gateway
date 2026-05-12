package handlers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
)

// freshExportStore seeds a memory store with the same deterministic
// mix freshStore uses, plus a few extras to stress filter combos that
// the export handler exposes (tenant, elevation_id).
func freshExportStore(t *testing.T) auditstore.Store {
	t.Helper()
	s := auditstore.NewMemoryStore(100)
	now := time.Now().UTC()

	make := func(d time.Duration, decision audit.Decision, tool, agent, tenant, elevation string) audit.Event {
		e := audit.NewEvent(decision, tool)
		e.Timestamp = now.Add(d).Format(time.RFC3339Nano)
		e.AgentID = agent
		e.Tenant = tenant
		e.ElevationID = elevation
		e.LatencyMS = 42
		return e
	}

	for _, e := range []audit.Event{
		make(0, audit.DecisionAllow, "read_invoice", "agent-a", "acme", ""),
		make(time.Second, audit.DecisionBlock, "send_email", "agent-b", "acme", ""),
		make(2*time.Second, audit.DecisionAllow, "send_email", "agent-a", "globex", "elev-7"),
		make(3*time.Second, audit.DecisionAllow, "read_invoice", "agent-b", "globex", ""),
		make(4*time.Second, audit.DecisionBlock, "delete_record", "agent-a", "acme", "elev-7"),
	} {
		if err := s.Insert(context.Background(), e); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
	return s
}

func newExportRequest(t *testing.T, query, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit/export?"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestAdminAuditExport_Auth(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)

	t.Run("no token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "", ""))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", rr.Code)
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "", "nope"))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", rr.Code)
		}
	})
	t.Run("right token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "", "secret"))
		if rr.Code != http.StatusOK {
			t.Errorf("want 200, got %d", rr.Code)
		}
	})
}

func TestAdminAuditExport_NoStoreReturns503(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: nil,
	}
	h := NewAdminAuditExportHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newExportRequest(t, "", "secret"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", rr.Code)
	}
}

func TestAdminAuditExport_RejectsBadFormat(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newExportRequest(t, "format=xml", "secret"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestAdminAuditExport_RejectsBadFromTo(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)
	for _, q := range []string{"from=not-a-date", "to=also-bad"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, q, "secret"))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("query %q: want 400, got %d", q, rr.Code)
		}
	}
}

// CSV header columns are part of the public contract — downstream
// pipelines (compliance pack tooling, Excel imports) read positionally.
// This test pins the order; new columns get appended at the end, never
// inserted in the middle. If you need to change this, plan a versioned
// rollout with the downstream consumer.
func TestAdminAuditExport_CSVHeaderIsStable(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newExportRequest(t, "format=csv", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	cr := csv.NewReader(rr.Body)
	header, err := cr.Read()
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	want := []string{
		"ts", "event", "schema_version", "decision", "check", "reason",
		"tenant", "agent_id", "session_id", "tool", "arg_keys",
		"capability_token_id", "root_capability_token_id", "caveat_count",
		"pending_id", "decided_by", "intent_summary", "latency_ms",
		"remote_ip", "upstream_status", "requires_step_up", "elevation_id",
	}
	if len(header) != len(want) {
		t.Fatalf("header length: want %d, got %d (header=%v)", len(want), len(header), header)
	}
	for i, col := range want {
		if header[i] != col {
			t.Errorf("col %d: want %q, got %q", i, col, header[i])
		}
	}
}

// CSV body should emit one row per event (plus the header row). The
// store has 5 events; the export should contain 6 records total.
func TestAdminAuditExport_CSVRowCount(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newExportRequest(t, "format=csv", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	cr := csv.NewReader(rr.Body)
	records, err := cr.ReadAll()
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(records) != 6 {
		t.Errorf("want 6 records (1 header + 5 events), got %d", len(records))
	}
}

// NDJSON body should be one JSON event per line, all parseable.
func TestAdminAuditExport_NDJSON(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newExportRequest(t, "format=json", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type: want application/x-ndjson, got %q", ct)
	}
	scanner := bufio.NewScanner(rr.Body)
	count := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("line %d not parseable JSON: %v (line=%q)", count, err, string(line))
		}
		if ev.Timestamp == "" {
			t.Errorf("line %d missing ts", count)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	if count != 5 {
		t.Errorf("want 5 events, got %d", count)
	}
}

// Content-Disposition must be an attachment with a filename that
// browsers will use as the download name. Tenant + UTC timestamp
// in the name lets operators tell two exports apart.
func TestAdminAuditExport_ContentDisposition(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)

	t.Run("csv unscoped", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "format=csv", "secret"))
		cd := rr.Header().Get("Content-Disposition")
		if !strings.HasPrefix(cd, "attachment; filename=") {
			t.Errorf("Content-Disposition: %q", cd)
		}
		if !strings.Contains(cd, "intentgate-audit-all-") {
			t.Errorf("want filename to start with intentgate-audit-all-: got %q", cd)
		}
		if !strings.Contains(cd, ".csv") {
			t.Errorf("want .csv extension: got %q", cd)
		}
	})
	t.Run("json with tenant", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "format=json&tenant=acme", "secret"))
		cd := rr.Header().Get("Content-Disposition")
		if !strings.Contains(cd, "intentgate-audit-acme-") {
			t.Errorf("want filename to carry tenant: got %q", cd)
		}
		if !strings.Contains(cd, ".ndjson") {
			t.Errorf("want .ndjson extension: got %q", cd)
		}
	})
}

// Filters must flow through to the store identically to the existing
// /v1/admin/audit query handler. We rely on the same QueryFilter
// struct, so this is mostly defending against an accidental drop of
// a query param mapping.
func TestAdminAuditExport_Filters(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"all", "format=json", 5},
		{"agent-a", "format=json&agent_id=agent-a", 3},
		{"send_email", "format=json&tool=send_email", 2},
		{"blocks only", "format=json&decision=block", 2},
		{"tenant acme", "format=json&tenant=acme", 3},
		{"tenant globex", "format=json&tenant=globex", 2},
		{"elevation elev-7", "format=json&elevation_id=elev-7", 2},
		{"no match", "format=json&agent_id=nope", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, newExportRequest(t, tc.query, "secret"))
			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d (body=%s)", rr.Code, rr.Body.String())
			}
			lines := bytes.Split(bytes.TrimSpace(rr.Body.Bytes()), []byte("\n"))
			// Empty body should not count as one line.
			got := 0
			for _, l := range lines {
				if len(bytes.TrimSpace(l)) > 0 {
					got++
				}
			}
			if got != tc.want {
				t.Errorf("want %d events, got %d", tc.want, got)
			}
		})
	}
}

// Per-tenant admin tokens force their tenant onto the export filter
// (the cross-tenant query is rejected with 403). Superadmin with no
// tenant binding can pass any tenant.
func TestAdminAuditExport_PerTenantAdminScoping(t *testing.T) {
	cfg := AdminConfig{
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:   "super",
		TenantAdmins: map[string]string{"acme": "acme-token"},
		AuditStore:   freshExportStore(t),
	}
	h := NewAdminAuditExportHandler(cfg)

	t.Run("per-tenant token forced", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "format=json", "acme-token"))
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		// Only acme rows should appear.
		dec := json.NewDecoder(rr.Body)
		count := 0
		for {
			var ev audit.Event
			if err := dec.Decode(&ev); err != nil {
				break
			}
			if ev.Tenant != "acme" {
				t.Errorf("got cross-tenant row: tenant=%q", ev.Tenant)
			}
			count++
		}
		if count != 3 {
			t.Errorf("want 3 acme rows, got %d", count)
		}
	})

	t.Run("per-tenant token rejects cross-tenant query", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "format=json&tenant=globex", "acme-token"))
		if rr.Code != http.StatusForbidden {
			t.Errorf("want 403, got %d", rr.Code)
		}
	})

	t.Run("superadmin with tenant honors it", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, newExportRequest(t, "format=json&tenant=globex", "super"))
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		dec := json.NewDecoder(rr.Body)
		count := 0
		for {
			var ev audit.Event
			if err := dec.Decode(&ev); err != nil {
				break
			}
			if ev.Tenant != "globex" {
				t.Errorf("got cross-tenant row: tenant=%q", ev.Tenant)
			}
			count++
		}
		if count != 2 {
			t.Errorf("want 2 globex rows, got %d", count)
		}
	})
}

// Spot-check that one CSV row encodes the scalar fields as we expect.
// arg_keys joins with semicolons; numeric columns serialize as base-10
// strings.
func TestAdminAuditExport_CSVRowEncoding(t *testing.T) {
	s := auditstore.NewMemoryStore(100)
	e := audit.NewEvent(audit.DecisionAllow, "read_invoice")
	e.Timestamp = "2026-05-12T10:00:00Z"
	e.AgentID = "agent-a"
	e.SessionID = "sess-1"
	e.Tenant = "acme"
	e.ArgKeys = []string{"id", "scope"}
	e.LatencyMS = 17
	e.UpstreamStatus = 200
	e.RequiresStepUp = true
	e.ElevationID = "elev-9"
	if err := s.Insert(context.Background(), e); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: s,
	}
	h := NewAdminAuditExportHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newExportRequest(t, "format=csv", "secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	cr := csv.NewReader(rr.Body)
	records, err := cr.ReadAll()
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want 2 records (header + 1), got %d", len(records))
	}
	row := records[1]
	if row[0] != "2026-05-12T10:00:00Z" {
		t.Errorf("ts col: %q", row[0])
	}
	if row[3] != "allow" {
		t.Errorf("decision col: %q", row[3])
	}
	if row[6] != "acme" {
		t.Errorf("tenant col: %q", row[6])
	}
	if row[7] != "agent-a" {
		t.Errorf("agent_id col: %q", row[7])
	}
	if row[10] != "id;scope" {
		t.Errorf("arg_keys col: %q (want id;scope)", row[10])
	}
	if row[17] != "17" {
		t.Errorf("latency_ms col: %q", row[17])
	}
	if row[19] != "200" {
		t.Errorf("upstream_status col: %q", row[19])
	}
	if row[20] != "true" {
		t.Errorf("requires_step_up col: %q", row[20])
	}
	if row[21] != "elev-9" {
		t.Errorf("elevation_id col: %q", row[21])
	}
	// Sanity: row width matches header width.
	if len(row) != len(records[0]) {
		t.Errorf("row width %d != header width %d", len(row), len(records[0]))
	}
}

// exportFilename produces deterministic prefixes and respects the
// "all" fallback for unscoped exports.
func TestExportFilename(t *testing.T) {
	f := exportFilename("acme", "csv")
	if !strings.HasPrefix(f, "intentgate-audit-acme-") || !strings.HasSuffix(f, ".csv") {
		t.Errorf("acme csv: %q", f)
	}
	f2 := exportFilename("", "ndjson")
	if !strings.HasPrefix(f2, "intentgate-audit-all-") || !strings.HasSuffix(f2, ".ndjson") {
		t.Errorf("unscoped ndjson: %q", f2)
	}
}

// eventToCSVRow column count must match exportCSVHeader column count
// at all times. A mismatch is a guaranteed runtime corruption that
// vet won't catch, so we test it directly.
func TestEventToCSVRow_WidthMatchesHeader(t *testing.T) {
	e := audit.NewEvent(audit.DecisionAllow, "noop")
	if got, want := len(eventToCSVRow(e)), len(exportCSVHeader); got != want {
		t.Errorf("row width %d != header width %d", got, want)
	}
}

// Tiny sanity that strconv-based integer rendering of zero values
// doesn't produce empty strings (CSV readers MIGHT silently swallow
// empty integer columns, so we want literal "0").
func TestEventToCSVRow_ZeroValuesAreLiteralZero(t *testing.T) {
	e := audit.NewEvent(audit.DecisionAllow, "noop")
	row := eventToCSVRow(e)
	// latency_ms is column 17 per the header.
	if row[17] != strconv.Itoa(0) {
		t.Errorf("latency_ms zero rendering: %q", row[17])
	}
}
