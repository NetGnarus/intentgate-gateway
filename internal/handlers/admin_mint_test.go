package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/capability"
)

// recEmitter captures audit events for assertions in tests.
type recEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recEmitter) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func mintRequest(t *testing.T, body string, adminToken string, cfg AdminConfig) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/mint", strings.NewReader(body))
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewAdminMintHandler(cfg).ServeHTTP(rec, req)
	return rec.Result()
}

func TestAdminMint_Success(t *testing.T) {
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	rec := &recEmitter{}
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  masterKey,
		Audit:      rec,
	}

	body := `{"subject":"finance-copilot","ttl_seconds":60,"tools":["read_invoice","list_invoices"],"max_calls":50}`
	resp := mintRequest(t, body, "secret", cfg)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}

	var out struct {
		Token     string `json:"token"`
		JTI       string `json:"jti"`
		Subject   string `json:"subject"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Token == "" || out.JTI == "" {
		t.Fatalf("response missing token/jti: %+v", out)
	}
	if out.Subject != "finance-copilot" {
		t.Errorf("subject mismatch: got %q", out.Subject)
	}
	if out.ExpiresAt == "" {
		t.Errorf("expires_at empty for non-zero ttl")
	}

	// Verify the token actually round-trips and is signed under the
	// master key the handler was given.
	tok, err := capability.Decode(out.Token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if err := tok.Verify(masterKey); err != nil {
		t.Fatalf("verify under master key: %v", err)
	}
	if tok.Subject != "finance-copilot" {
		t.Errorf("token subject mismatch: %q", tok.Subject)
	}

	// First caveat must be the agent-lock binding to subject.
	if len(tok.Caveats) == 0 || tok.Caveats[0].Type != capability.CaveatAgentLock || tok.Caveats[0].Agent != "finance-copilot" {
		t.Errorf("expected agent-lock caveat first, got %+v", tok.Caveats)
	}

	// Confirm the tool whitelist + max-calls caveats made it in.
	var sawWhitelist, sawMaxCalls bool
	for _, c := range tok.Caveats {
		switch c.Type {
		case capability.CaveatToolWhitelist:
			sawWhitelist = true
			if len(c.Tools) != 2 {
				t.Errorf("expected 2 tools in whitelist, got %v", c.Tools)
			}
		case capability.CaveatMaxCalls:
			sawMaxCalls = true
			if c.MaxCalls != 50 {
				t.Errorf("max_calls mismatch: got %d", c.MaxCalls)
			}
		}
	}
	if !sawWhitelist {
		t.Error("missing tool-whitelist caveat")
	}
	if !sawMaxCalls {
		t.Error("missing max-calls caveat")
	}

	// Audit recorded.
	if len(rec.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(rec.events))
	}
	ev := rec.events[0]
	// "admin/mint" is passed as the Tool label so audit pipelines can
	// route it next to /v1/admin/revoke events.
	if ev.Tool != "admin/mint" {
		t.Errorf("audit tool: got %q want admin/mint", ev.Tool)
	}
	if ev.CapabilityTokenID != tok.ID {
		t.Errorf("audit jti mismatch: got %q want %q", ev.CapabilityTokenID, tok.ID)
	}
	if ev.AgentID != "finance-copilot" {
		t.Errorf("audit agent_id: got %q", ev.AgentID)
	}
}

func TestAdminMint_NoTTL_NoExpiry(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
	resp := mintRequest(t, `{"subject":"agent-x"}`, "secret", cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var out struct {
		ExpiresAt string `json:"expires_at"`
		Token     string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.ExpiresAt != "" {
		t.Errorf("expected empty expires_at, got %q", out.ExpiresAt)
	}
	tok, err := capability.Decode(out.Token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range tok.Caveats {
		if c.Type == capability.CaveatExpiry {
			t.Errorf("did not expect expiry caveat, got %v", c)
		}
	}
}

func TestAdminMint_BadAuth(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
	cases := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"wrong", "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := mintRequest(t, `{"subject":"x"}`, tc.token, cfg)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", resp.StatusCode)
			}
		})
	}
}

func TestAdminMint_NoMasterKey(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
	}
	resp := mintRequest(t, `{"subject":"x"}`, "secret", cfg)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", resp.StatusCode)
	}
}

func TestAdminMint_Validation(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
	cases := []struct {
		name string
		body string
	}{
		{"missing subject", `{"ttl_seconds":60}`},
		{"empty subject", `{"subject":""}`},
		{"negative ttl", `{"subject":"x","ttl_seconds":-1}`},
		{"negative max_calls", `{"subject":"x","max_calls":-5}`},
		{"unknown field", `{"subject":"x","foo":"bar"}`},
		{"malformed json", `{"subject":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := mintRequest(t, tc.body, "secret", cfg)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("got %d want 400 (body=%s)", resp.StatusCode, tc.body)
			}
		})
	}
}

func TestAdminMint_TTLProducesExpiry(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
	before := time.Now().UTC()
	body := `{"subject":"agent","ttl_seconds":3600}`
	resp := mintRequest(t, body, "secret", cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var out struct{ Token, ExpiresAt string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	tok, err := capability.Decode(out.Token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var sawExpiry bool
	for _, c := range tok.Caveats {
		if c.Type == capability.CaveatExpiry {
			sawExpiry = true
			delta := c.Expiry - before.Unix()
			if delta < 3500 || delta > 3700 {
				t.Errorf("expiry %d not within ~3600s window of before %d", c.Expiry, before.Unix())
			}
		}
	}
	if !sawExpiry {
		t.Error("expected expiry caveat from non-zero ttl")
	}
}

func TestAdminMint_EncodedTokenIsBase64URL(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
	resp := mintRequest(t, `{"subject":"x"}`, "secret", cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out struct{ Token string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if _, err := base64.RawURLEncoding.DecodeString(out.Token); err != nil {
		t.Fatalf("token is not base64url: %v", err)
	}
}

// Sanity check: handler shouldn't be confused by extra whitespace in
// the optional tools list — empty/whitespace entries are dropped before
// the caveat is added.
func TestAdminMint_DropsEmptyToolEntries(t *testing.T) {
	cfg := AdminConfig{
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
	body := `{"subject":"x","tools":["a"," ","b",""]}`
	resp := mintRequest(t, body, "secret", cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out struct{ Token string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	tok, _ := capability.Decode(out.Token)
	for _, c := range tok.Caveats {
		if c.Type == capability.CaveatToolWhitelist {
			if len(c.Tools) != 2 {
				t.Errorf("expected 2 cleaned tools, got %v", c.Tools)
			}
		}
	}
}

// Compile-time assertion that the sample request body parses with the
// same JSON shape we document, so the README example doesn't drift
// from the schema.
var _ = bytes.NewReader([]byte(`{"subject":"x","ttl_seconds":60,"tools":["a"],"max_calls":1}`))
