package capability

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// --- Mint / Verify --------------------------------------------------------

func TestMintProducesValidToken(t *testing.T) {
	key := mustKey(t)
	tok, err := Mint(key, MintOptions{Subject: "agent-x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Verify(key); err != nil {
		t.Fatalf("freshly minted token failed verify: %v", err)
	}
	if tok.Subject != "agent-x" {
		t.Errorf("subject=%q want agent-x", tok.Subject)
	}
	if tok.Version != SchemaVersion {
		t.Errorf("version=%d want %d", tok.Version, SchemaVersion)
	}
	if tok.ID == "" {
		t.Errorf("expected non-empty jti")
	}
	if tok.IssuedAt == 0 {
		t.Errorf("expected non-zero iat")
	}
	// Root tokens have RootID == ID and IsRoot() reports true.
	if tok.RootID != tok.ID {
		t.Errorf("root token: RootID=%q ID=%q (should match)", tok.RootID, tok.ID)
	}
	if !tok.IsRoot() {
		t.Errorf("freshly minted token should be IsRoot()")
	}
	// Tenant defaults to "default" when MintOptions.Tenant is empty.
	if tok.Tenant != DefaultTenant {
		t.Errorf("tenant=%q want %q", tok.Tenant, DefaultTenant)
	}
	// Mint should auto-prepend an agent_lock caveat.
	if len(tok.Caveats) == 0 || tok.Caveats[0].Type != CaveatAgentLock {
		t.Errorf("first caveat should be agent_lock, got %+v", tok.Caveats)
	}
}

func TestMintRequiresSubject(t *testing.T) {
	_, err := Mint(mustKey(t), MintOptions{})
	if err == nil {
		t.Fatalf("expected error when subject is empty")
	}
}

func TestMintRequiresMasterKey(t *testing.T) {
	_, err := Mint(nil, MintOptions{Subject: "x"})
	if err == nil {
		t.Fatalf("expected error when master key is empty")
	}
}

// --- Tampering detection --------------------------------------------------

func TestVerifyDetectsAddedCaveat(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "x"})
	// Attacker appends a caveat without re-signing.
	tok.Caveats = append(tok.Caveats, Caveat{
		Type:  CaveatToolWhitelist,
		Tools: []string{"transfer_funds"},
	})
	if err := tok.Verify(key); err == nil {
		t.Fatalf("expected verify failure on tampered caveat")
	}
}

func TestVerifyDetectsModifiedSubject(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "alice"})
	tok.Subject = "mallory"
	if err := tok.Verify(key); err == nil {
		t.Fatalf("expected verify failure on subject swap")
	}
}

func TestVerifyDetectsWrongMasterKey(t *testing.T) {
	tok, _ := Mint(mustKey(t), MintOptions{Subject: "x"})
	if err := tok.Verify(mustKey(t)); err == nil {
		t.Fatalf("expected verify failure with wrong key")
	}
}

func TestVerifyDetectsTruncatedSignature(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "x"})
	tok.Signature = tok.Signature[:len(tok.Signature)-4]
	if err := tok.Verify(key); err == nil {
		t.Fatalf("expected verify failure on truncated signature")
	}
}

// --- Attenuation ----------------------------------------------------------

func TestAttenuateNeedsNoMasterKey(t *testing.T) {
	masterKey := mustKey(t)
	parent, _ := Mint(masterKey, MintOptions{
		Subject: "x",
		Caveats: []Caveat{
			{Type: CaveatToolWhitelist, Tools: []string{"a", "b", "c"}},
		},
	})

	// The party doing the attenuation does NOT have masterKey here:
	child, err := Attenuate(parent, Caveat{
		Type:  CaveatToolWhitelist,
		Tools: []string{"a"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// But the gateway, which DOES have masterKey, can still verify it:
	if err := child.Verify(masterKey); err != nil {
		t.Fatalf("attenuated token failed verify: %v", err)
	}
	// Child should have one more caveat than parent.
	if len(child.Caveats) != len(parent.Caveats)+1 {
		t.Errorf("child caveats=%d parent caveats=%d", len(child.Caveats), len(parent.Caveats))
	}
}

func TestAttenuateChainsMultipleSteps(t *testing.T) {
	key := mustKey(t)
	root, _ := Mint(key, MintOptions{Subject: "x"})
	step1, err := Attenuate(root, Caveat{Type: CaveatToolWhitelist, Tools: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	step2, err := Attenuate(step1, Caveat{Type: CaveatExpiry, Expiry: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := step2.Verify(key); err != nil {
		t.Fatalf("two-step attenuation failed verify: %v", err)
	}
	if len(step2.Caveats) != len(root.Caveats)+2 {
		t.Errorf("expected 2 extra caveats, got chain length %d (root had %d)",
			len(step2.Caveats), len(root.Caveats))
	}
}

func TestAttenuatePreservesRootID(t *testing.T) {
	key := mustKey(t)
	root, _ := Mint(key, MintOptions{Subject: "x"})
	if !root.IsRoot() {
		t.Fatal("Mint output should be IsRoot()")
	}
	child, err := Attenuate(root, Caveat{Type: CaveatToolWhitelist, Tools: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if child.RootID != root.RootID {
		t.Errorf("child.RootID=%q parent.RootID=%q (should match)", child.RootID, root.RootID)
	}
}

// TestAttenuateNarrowingRejectsBroaderTool verifies the central
// security property of Macaroon-style delegation: a child cannot widen
// its parent's tool whitelist. The chain commits to BOTH the parent's
// narrow caveat and the child's broader one, so caveat evaluation
// (which fails on the FIRST violation) blocks the call regardless of
// what the attenuating party tried to claim.
func TestAttenuateNarrowingRejectsBroaderTool(t *testing.T) {
	key := mustKey(t)
	parent, _ := Mint(key, MintOptions{
		Subject: "x",
		Caveats: []Caveat{{Type: CaveatToolWhitelist, Tools: []string{"a"}}},
	})
	// Malicious attenuator tries to "widen" by adding a broader allow.
	child, err := Attenuate(parent, Caveat{
		Type:  CaveatToolWhitelist,
		Tools: []string{"a", "b", "c"}, // broader than parent's [a]
	})
	if err != nil {
		t.Fatal(err)
	}
	// Verify still passes — the chain is well-formed.
	if err := child.Verify(key); err != nil {
		t.Fatalf("child verify: %v", err)
	}
	// But Check rejects a call to b: the parent's narrower caveat fires first.
	if err := child.Check(RequestContext{AgentID: "x", Tool: "b"}); err == nil {
		t.Errorf("expected Check to reject tool=b (parent caveat allows only [a])")
	}
}

func TestVerifyDetectsRootIDTamper(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "x"})
	tok.RootID = "spoofed-root"
	if err := tok.Verify(key); err == nil {
		t.Fatal("expected verify failure on tampered RootID")
	}
}

func TestMintAcceptsCustomTenant(t *testing.T) {
	key := mustKey(t)
	tok, err := Mint(key, MintOptions{Subject: "x", Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Tenant != "acme" {
		t.Errorf("tenant=%q want acme", tok.Tenant)
	}
	if err := tok.Verify(key); err != nil {
		t.Errorf("custom-tenant token failed verify: %v", err)
	}
}

func TestVerifyDetectsTenantTamper(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "x", Tenant: "acme"})
	// Attacker tries to pivot the token to a different tenant.
	tok.Tenant = "victim-corp"
	if err := tok.Verify(key); err == nil {
		t.Fatal("expected verify failure on cross-tenant pivot")
	}
}

func TestAttenuatePreservesTenant(t *testing.T) {
	key := mustKey(t)
	parent, _ := Mint(key, MintOptions{Subject: "x", Tenant: "acme"})
	child, err := Attenuate(parent, Caveat{Type: CaveatToolWhitelist, Tools: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if child.Tenant != "acme" {
		t.Errorf("child.Tenant=%q want acme", child.Tenant)
	}
	if err := child.Verify(key); err != nil {
		t.Errorf("attenuated token failed verify: %v", err)
	}
}

func TestCaveatCount(t *testing.T) {
	key := mustKey(t)
	root, _ := Mint(key, MintOptions{Subject: "x"})
	rootCount := root.CaveatCount()
	child, _ := Attenuate(root, Caveat{Type: CaveatToolWhitelist, Tools: []string{"a"}})
	if child.CaveatCount() != rootCount+1 {
		t.Errorf("child CaveatCount=%d, want %d", child.CaveatCount(), rootCount+1)
	}
}

// --- Caveat evaluation ----------------------------------------------------

func TestCheckExpiryRejectsExpired(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{
		Subject: "x",
		Expiry:  time.Now().Add(-time.Hour),
	})
	err := tok.Check(RequestContext{AgentID: "x", Tool: "read_invoice"})
	if err == nil {
		t.Fatalf("expected expiry failure")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expiry message, got %v", err)
	}
}

func TestCheckExpiryAllowsBeforeDeadline(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{
		Subject: "x",
		Expiry:  time.Now().Add(time.Hour),
	})
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "read_invoice"}); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestCheckAgentLock(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "alice"})

	if err := tok.Check(RequestContext{AgentID: "mallory", Tool: "read_invoice"}); err == nil {
		t.Fatalf("expected agent_lock failure")
	}
	if err := tok.Check(RequestContext{AgentID: "alice", Tool: "read_invoice"}); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestCheckToolWhitelist(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{
		Subject: "x",
		Caveats: []Caveat{{Type: CaveatToolWhitelist, Tools: []string{"read_invoice"}}},
	})
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "read_invoice"}); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "send_email"}); err == nil {
		t.Fatalf("expected fail for non-allowlisted tool")
	}
}

func TestCheckToolBlacklist(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{
		Subject: "x",
		Caveats: []Caveat{{Type: CaveatToolBlacklist, Tools: []string{"transfer_funds"}}},
	})
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "read_invoice"}); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "transfer_funds"}); err == nil {
		t.Fatalf("expected fail for blacklisted tool")
	}
}

func TestMaxCallsCaveatIsInformationalAtCapabilityLayer(t *testing.T) {
	// max_calls is enforced by the budget package, not capability.
	// At this layer it must pass; otherwise budgeted tokens couldn't
	// even reach the budget check.
	key := mustKey(t)
	tok, err := Mint(key, MintOptions{
		Subject: "x",
		Caveats: []Caveat{{Type: CaveatMaxCalls, MaxCalls: 5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Verify(key); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "read_invoice"}); err != nil {
		t.Fatalf("max_calls caveat must pass at capability layer, got: %v", err)
	}
}

func TestUnknownCaveatDeniesByDefault(t *testing.T) {
	key := mustKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "x"})
	tok.Caveats = append(tok.Caveats, Caveat{Type: "future_caveat_we_dont_understand"})
	if err := tok.Sign(key); err != nil { // re-sign so signature is valid
		t.Fatal(err)
	}
	if err := tok.Verify(key); err != nil {
		t.Fatalf("re-signed token should verify: %v", err)
	}
	if err := tok.Check(RequestContext{AgentID: "x", Tool: "anything"}); err == nil {
		t.Fatalf("expected deny on unknown caveat")
	}
}

func TestCheckNotBeforeRespected(t *testing.T) {
	key := mustKey(t)
	future := time.Now().Add(time.Hour)
	tok, _ := Mint(key, MintOptions{Subject: "x", NotBefore: future})
	err := tok.Check(RequestContext{AgentID: "x", Tool: "read_invoice"})
	if err == nil {
		t.Fatalf("expected nbf failure")
	}
}

// --- Encode / Decode / Header --------------------------------------------

func TestEncodeDecodeRoundTrip(t *testing.T) {
	key := mustKey(t)
	orig, _ := Mint(key, MintOptions{Subject: "x", Expiry: time.Now().Add(time.Minute)})
	encoded, err := orig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(key); err != nil {
		t.Fatalf("decoded token failed verify: %v", err)
	}
	if decoded.Subject != orig.Subject {
		t.Errorf("subject changed: %q != %q", decoded.Subject, orig.Subject)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode("not base64 ☠"); err == nil {
		t.Fatalf("expected base64 failure")
	}
	if _, err := Decode("dGhpcyBpcyBub3QgSlNPTg"); err == nil {
		t.Fatalf("expected JSON failure on non-token bytes")
	}
}

func TestFromAuthorizationHeader(t *testing.T) {
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"empty header", "", "", false},
		{"bearer with token", "Bearer abc123", "abc123", false},
		{"trims surrounding whitespace", "Bearer   abc  ", "abc", false},
		{"basic scheme rejected", "Basic abc", "", true},
		{"no scheme prefix rejected", "abc123", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromAuthorizationHeader(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestMasterKeyFromBase64(t *testing.T) {
	// Standard base64url with padding stripped — must decode.
	in := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	out, err := MasterKeyFromBase64(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 16 {
		t.Errorf("decoded key too short: %d", len(out))
	}
	// Empty rejected.
	if _, err := MasterKeyFromBase64(""); err == nil {
		t.Fatalf("expected error on empty input")
	}
	// Garbage rejected.
	if _, err := MasterKeyFromBase64("not!base64!at!all!"); err == nil {
		t.Fatalf("expected error on non-base64 input")
	}
}

// --- Step-up caveat ------------------------------------------------------

// A token carrying a signed step_up caveat round-trips through Encode +
// Decode + Verify and survives Check (capability layer treats it as
// informational; recency is enforced by Rego policies).
func TestStepUpCaveatRoundTrip(t *testing.T) {
	key := mustKey(t)
	stepUpAt := time.Now().UTC().Unix()
	tok, err := Mint(key, MintOptions{
		Subject: "alice",
		Caveats: []Caveat{{Type: CaveatStepUp, StepUpAt: stepUpAt}},
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := tok.Encode()
	if err != nil {
		t.Fatal(err)
	}
	round, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := round.Verify(key); err != nil {
		t.Fatalf("verify after encode/decode: %v", err)
	}

	// Last caveat should be the step_up with the same timestamp we
	// stamped. (Agent-lock is at index 0.)
	last := round.Caveats[len(round.Caveats)-1]
	if last.Type != CaveatStepUp {
		t.Fatalf("expected last caveat to be step_up, got %q", last.Type)
	}
	if last.StepUpAt != stepUpAt {
		t.Errorf("step_up_at=%d want %d", last.StepUpAt, stepUpAt)
	}

	// Check (caveat evaluation) should pass — step_up is informational
	// at the capability layer.
	if err := round.Check(RequestContext{AgentID: "alice", Tool: "anything"}); err != nil {
		t.Errorf("Check should accept step_up caveat: %v", err)
	}
}

// Tampering with the step_up timestamp breaks the chain signature.
func TestStepUpCaveatTamperingDetected(t *testing.T) {
	key := mustKey(t)
	tok, err := Mint(key, MintOptions{
		Subject: "alice",
		Caveats: []Caveat{{Type: CaveatStepUp, StepUpAt: 100}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the holder rewrote step_up_at to "just now" without
	// re-signing. Verify must reject.
	for i := range tok.Caveats {
		if tok.Caveats[i].Type == CaveatStepUp {
			tok.Caveats[i].StepUpAt = time.Now().UTC().Unix()
		}
	}
	if err := tok.Verify(key); err == nil {
		t.Fatalf("Verify should fail after step_up_at tampering")
	}
}

// A step_up caveat with a negative timestamp is rejected at Check
// time (defensive — a positive caveat type is fine; the constraint
// is on the value).
func TestStepUpCaveatNegativeTimestampRejected(t *testing.T) {
	key := mustKey(t)
	tok, err := Mint(key, MintOptions{
		Subject: "alice",
		Caveats: []Caveat{{Type: CaveatStepUp, StepUpAt: -1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Verify(key); err != nil {
		t.Fatalf("Verify should succeed (chain still well-formed): %v", err)
	}
	if err := tok.Check(RequestContext{AgentID: "alice", Tool: "anything"}); err == nil {
		t.Errorf("Check should reject negative step_up_at")
	}
}

// Attenuation onto a token without step_up can ADD a step_up caveat,
// which is what Pro will do once it has its own per-operator path.
func TestAttenuateAppendsStepUpCaveat(t *testing.T) {
	key := mustKey(t)
	parent, err := Mint(key, MintOptions{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	stepUpAt := time.Now().UTC().Unix()
	child, err := Attenuate(parent, Caveat{Type: CaveatStepUp, StepUpAt: stepUpAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Verify(key); err != nil {
		t.Fatalf("attenuated child should verify: %v", err)
	}
	if got := child.Caveats[len(child.Caveats)-1]; got.Type != CaveatStepUp || got.StepUpAt != stepUpAt {
		t.Errorf("last caveat on child = %+v; want step_up @ %d", got, stepUpAt)
	}
}
