package extractor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// canned response a test server returns
const cannedResponseJSON = `{
  "intent": {
    "summary": "Process AP invoices",
    "allowed_tools": ["read_invoice","record_in_ledger"],
    "forbidden_tools": ["send_email","transfer_funds"],
    "confidence": 0.85
  },
  "model": "stub-v1",
  "latency_ms": 1
}`

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New(srv.URL, 16)
	return srv, c
}

// --- Allows -------------------------------------------------------------

func TestAllowsRespectsForbiddenList(t *testing.T) {
	i := &ExtractedIntent{
		AllowedTools:   []string{"read_invoice", "send_email"},
		ForbiddenTools: []string{"send_email"},
	}
	// even though send_email is in allowed, forbidden wins
	if ok, _ := i.Allows("send_email"); ok {
		t.Errorf("expected forbidden to override allowed")
	}
}

func TestAllowsAllowsItemInAllowedList(t *testing.T) {
	i := &ExtractedIntent{AllowedTools: []string{"read_invoice"}}
	if ok, _ := i.Allows("read_invoice"); !ok {
		t.Errorf("expected read_invoice to be allowed")
	}
	if ok, _ := i.Allows("send_email"); ok {
		t.Errorf("expected send_email to be denied (not in list)")
	}
}

func TestAllowsEmptyAllowListMeansForbiddenOnly(t *testing.T) {
	// "I don't know what's needed; just block destructive things."
	i := &ExtractedIntent{
		AllowedTools:   nil,
		ForbiddenTools: []string{"transfer_funds"},
	}
	if ok, _ := i.Allows("read_invoice"); !ok {
		t.Errorf("expected read_invoice allowed when allow list is empty")
	}
	if ok, _ := i.Allows("transfer_funds"); ok {
		t.Errorf("expected transfer_funds blocked even with empty allow list")
	}
}

// --- Extract roundtrip --------------------------------------------------

func TestExtractRoundTrip(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/extract" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req extractRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Prompt == "" || req.AgentID == "" {
			t.Errorf("expected prompt and agent_id, got %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cannedResponseJSON))
	})

	intent, err := c.Extract(context.Background(), "Process AP invoices", "finance-copilot-v3")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Summary != "Process AP invoices" {
		t.Errorf("summary: %q", intent.Summary)
	}
	if !contains(intent.AllowedTools, "read_invoice") {
		t.Errorf("allowed_tools missing read_invoice: %v", intent.AllowedTools)
	}
}

func TestExtractRejectsEmptyPrompt(t *testing.T) {
	c := New("http://unused", 16)
	if _, err := c.Extract(context.Background(), "", ""); err == nil {
		t.Errorf("expected error on empty prompt")
	}
}

func TestExtractRejectsMissingBaseURL(t *testing.T) {
	c := New("", 16)
	if _, err := c.Extract(context.Background(), "anything", ""); err == nil {
		t.Errorf("expected error on empty base URL")
	}
}

func TestExtractPropagatesNonOK(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	})
	_, err := c.Extract(context.Background(), "x", "")
	if err == nil {
		t.Fatalf("expected error on 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

// --- Cache --------------------------------------------------------------

func TestCacheHitAvoidsSecondCall(t *testing.T) {
	var calls int64
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cannedResponseJSON))
	})

	if _, err := c.Extract(context.Background(), "Same prompt", "agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extract(context.Background(), "Same prompt", "agent"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("expected 1 upstream call, got %d", got)
	}
}

func TestCacheMissOnDifferentPrompt(t *testing.T) {
	var calls int64
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cannedResponseJSON))
	})

	_, _ = c.Extract(context.Background(), "Prompt A", "agent")
	_, _ = c.Extract(context.Background(), "Prompt B", "agent")
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("expected 2 upstream calls, got %d", got)
	}
}

func TestCacheDisabledWhenSizeZero(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cannedResponseJSON))
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, 0) // cache disabled
	_, _ = c.Extract(context.Background(), "Same prompt", "agent")
	_, _ = c.Extract(context.Background(), "Same prompt", "agent")
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("expected 2 upstream calls with cache disabled, got %d", got)
	}
}

// --- Timeout / context --------------------------------------------------

func TestExtractRespectsTimeout(t *testing.T) {
	// Handler sleeps for longer than the client's timeout, then returns
	// normally. We don't wait on r.Context().Done() because connection
	// teardown propagation across the loopback can lag on macOS, which
	// makes srv.Close() block at the end of the test. A bounded sleep
	// keeps cleanup fast and still proves the timeout path works.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cannedResponseJSON))
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, 0)
	c.Timeout = 50 * time.Millisecond
	if _, err := c.Extract(context.Background(), "slow", ""); err == nil {
		t.Errorf("expected timeout error")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
