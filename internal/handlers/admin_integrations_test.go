package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/siem"
)

// fakeReporter implements siem.StatusReporter for tests without
// pulling in the real emitters (which would need HTTP servers).
type fakeReporter struct{ s siem.Status }

func (f *fakeReporter) Status() siem.Status { return f.s }

func TestAdminIntegrations_RequiresToken(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
	}
	h := NewAdminIntegrationsHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/integrations", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without token, got %d", rr.Code)
	}
}

func TestAdminIntegrations_ReturnsStubsWhenNoneWired(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		// nil reporters
	}
	h := NewAdminIntegrationsHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/integrations", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	var got struct {
		Integrations []siem.Status `json:"integrations"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Integrations) != 3 {
		t.Fatalf("want 3 stubs (splunk+datadog+sentinel), got %d", len(got.Integrations))
	}
	for _, s := range got.Integrations {
		if s.Configured {
			t.Errorf("%s: Configured=true but no reporter wired", s.Name)
		}
	}
}

func TestAdminIntegrations_ReturnsWiredStatus(t *testing.T) {
	splunk := &fakeReporter{s: siem.Status{
		Name:         "splunk",
		Configured:   true,
		Endpoint:     "https://splunk.example:8088/services/collector",
		TotalEvents:  42,
		DroppedCount: 1,
		LastFlushTs:  time.Now().UTC(),
	}}
	cfg := AdminConfig{
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:    "secret",
		SIEMReporters: []siem.StatusReporter{splunk},
	}
	h := NewAdminIntegrationsHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/integrations", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var got struct {
		Integrations []siem.Status `json:"integrations"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Integrations) != 3 {
		t.Fatalf("want 3 entries (splunk wired, datadog+sentinel stubs), got %d", len(got.Integrations))
	}
	if got.Integrations[0].Name != "splunk" || !got.Integrations[0].Configured {
		t.Errorf("splunk entry wrong: %+v", got.Integrations[0])
	}
	if got.Integrations[0].TotalEvents != 42 {
		t.Errorf("splunk TotalEvents = %d, want 42", got.Integrations[0].TotalEvents)
	}
	if got.Integrations[1].Name != "datadog" || got.Integrations[1].Configured {
		t.Errorf("datadog stub wrong: %+v", got.Integrations[1])
	}
	if got.Integrations[2].Name != "sentinel" || got.Integrations[2].Configured {
		t.Errorf("sentinel stub wrong: %+v", got.Integrations[2])
	}
}
