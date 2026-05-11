// Package capability implements Macaroon-style capability tokens for
// authorizing tool calls through the IntentGate gateway.
//
// Threat model. The master key never leaves the gateway. Tokens are
// minted by a trusted authority (the gateway itself, or a co-located
// minting service) and handed to agents. Agents include the token in
// the HTTP Authorization header on every tool call. The gateway
// recomputes the HMAC chain under its master key and rejects anything
// that doesn't match.
//
// Attenuation. A holder can derive a strictly more restrictive child
// token by appending a new caveat and HMAC'ing it under the parent's
// signature as the new key. Crucially this requires no access to the
// master key. The chained-HMAC construction (originally from Macaroons,
// Birgisson et al., 2014) guarantees that an attenuated token's chain
// can only narrow, never widen, the parent's scope: removing a caveat
// breaks the signature.
//
// What this package does NOT do.
//
//   - Persistence: tokens are stateless, identified by jti, and
//     evaluated only by signature and caveats. Per-token state (call
//     counters, taint, revocation) lives elsewhere (Redis, in a later
//     session).
//   - Issuance policy: deciding *who* gets *what* token belongs to a
//     higher layer. This package answers "is this token valid and does
//     it allow the requested call?" — not "should this user have a
//     token for that scope?"
//   - Encryption: tokens are signed but not encrypted. Anyone holding
//     a token's bytes can read its caveats. Treat them like bearer
//     credentials: don't log them, transmit over TLS only.
package capability

import (
	"encoding/json"
	"errors"
)

// SchemaVersion is the wire-format version of a capability token. The
// gateway accepts only this version; older tokens must be re-minted.
//
// v2 (gateway 0.7+) adds [Token.RootID] so attenuated children carry a
// distinct ID per hop while still anchoring back to the chain root.
// v1 tokens (gateway 0.1–0.6) have no RootID and are NOT accepted by
// v2 verifiers.
//
// v3 (gateway 0.9+) adds [Token.Tenant] so a single deployment can
// authorize traffic from multiple isolated trust domains (org →
// project → agent in the pitch's hierarchy). The tenant claim is
// signed in the canonicalPayload, so an attacker cannot pivot a
// stolen token from tenant A to tenant B without the master key.
// v2 tokens are NOT accepted by v3 verifiers. There is no in-flight
// migration: redeploy the gateway at v0.9, re-mint outstanding tokens.
const SchemaVersion = 3

// Token is the on-wire and in-memory representation of a capability.
//
// Field order matters for canonical serialization: the JSON encoder
// emits struct fields in declaration order, and the HMAC chain commits
// to those bytes. Reordering fields will silently invalidate every
// pre-existing token.
//
// Identity model. Every hop in a delegation chain has its own [ID]
// (jti) so revocation, audit citations, and budget counters can address
// a single hop without affecting siblings. [RootID] anchors back to the
// original Mint — the SOC analyst uses it to reconstruct the full tree.
// On root tokens (Mint output) RootID == ID. On attenuated children
// (Attenuate output) RootID == parent.RootID and ID is a fresh
// time-prefixed random.
type Token struct {
	Version int    `json:"v"`
	ID      string `json:"jti"`
	RootID  string `json:"root_jti"`
	Issuer  string `json:"iss"`
	// Tenant is the trust-domain namespace this token authorizes
	// traffic for ("acme", "tenant-a", "default"). Signed in the
	// canonicalPayload so a stolen token cannot pivot tenants.
	// Mint defaults this to "default" when the caller doesn't set
	// one — single-tenant deployments stay simple while multi-tenant
	// deployments get isolation.
	Tenant    string   `json:"tenant"`
	Subject   string   `json:"sub"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	Caveats   []Caveat `json:"cav,omitempty"`
	Signature string   `json:"sig"`
}

// DefaultTenant is the value Mint stamps when MintOptions.Tenant is
// empty. Single-tenant deployments live entirely in this namespace
// without explicit configuration.
const DefaultTenant = "default"

// Caveat type identifiers. New types must be added here AND handled in
// the evaluator (see check.go); unknown types are denied by default.
const (
	// CaveatExpiry — request time must be strictly less than Expiry (unix seconds).
	CaveatExpiry = "exp"
	// CaveatToolWhitelist — request tool must appear in Tools.
	CaveatToolWhitelist = "tool_allow"
	// CaveatToolBlacklist — request tool must NOT appear in Tools.
	CaveatToolBlacklist = "tool_deny"
	// CaveatAgentLock — request agent ID must equal Agent.
	// Mint always prepends one of these to bind a token to its subject.
	CaveatAgentLock = "agent_lock"
	// CaveatMaxCalls — total tool-call count for this token must stay
	// at or below MaxCalls. Enforcement requires persistent state and
	// happens in the budget package, NOT in capability.Check; the
	// capability layer treats this caveat as informational and accepts
	// it without checking. The signed presence of the caveat in the
	// chain ensures agents can't strip or alter the limit.
	CaveatMaxCalls = "max_calls"
	// CaveatStepUp — token was minted after a fresh step-up
	// authentication factor (TOTP / WebAuthn / hardware key) was
	// verified out-of-band by the operator. StepUpAt carries the
	// unix-seconds timestamp of the step-up event. The capability
	// layer accepts this caveat without enforcing recency — recency
	// checks belong in the Rego policy
	// (`time.now_ns()/1e9 - input.capability.step_up_at < 300`),
	// because what "fresh enough" means depends on the operation:
	// 5 minutes for a high-risk mint, 30 seconds for a policy delete.
	// The signed presence of the caveat in the chain ensures a holder
	// cannot forge a fake step-up annotation.
	CaveatStepUp = "step_up"
)

// Caveat is a structured restriction recorded in a token's chain.
//
// Caveats use a tagged-union JSON shape rather than per-type Go types
// because (a) the wire format must round-trip cleanly through plain
// JSON and (b) the canonical bytes input to the HMAC chain need to be
// stable and inspectable. A future migration to typed caveats is
// possible without changing the chain construction.
type Caveat struct {
	Type     string   `json:"t"`
	Tools    []string `json:"tools,omitempty"`
	Agent    string   `json:"agent,omitempty"`
	Expiry   int64    `json:"exp,omitempty"`
	MaxCalls int      `json:"max_calls,omitempty"`
	// StepUpAt is the unix-seconds timestamp at which the operator
	// completed an out-of-band step-up authentication factor (TOTP,
	// WebAuthn, hardware key). Only meaningful when Type is
	// [CaveatStepUp]. Used by Rego policies to gate high-risk
	// operations on recent fresh-factor presence. Signed in the
	// chain so a holder cannot fabricate one.
	StepUpAt int64 `json:"step_up_at,omitempty"`
}

// canonicalPayload returns the bytes that seed the HMAC chain. It
// excludes Caveats and Signature; those are absorbed by the chain.
//
// CAUTION: changing this struct's field order or set of fields is a
// breaking wire-format change. Bump SchemaVersion if you do.
func (t *Token) canonicalPayload() ([]byte, error) {
	body := struct {
		Version   int    `json:"v"`
		ID        string `json:"jti"`
		RootID    string `json:"root_jti"`
		Issuer    string `json:"iss"`
		Tenant    string `json:"tenant"`
		Subject   string `json:"sub"`
		IssuedAt  int64  `json:"iat"`
		NotBefore int64  `json:"nbf,omitempty"`
	}{
		Version:   t.Version,
		ID:        t.ID,
		RootID:    t.RootID,
		Issuer:    t.Issuer,
		Tenant:    t.Tenant,
		Subject:   t.Subject,
		IssuedAt:  t.IssuedAt,
		NotBefore: t.NotBefore,
	}
	return json.Marshal(body)
}

// canonicalBytes returns the bytes used as input to the HMAC step that
// folds this caveat into the signature chain. encoding/json emits
// struct fields in declaration order, giving a stable representation.
func (c *Caveat) canonicalBytes() ([]byte, error) {
	return json.Marshal(c)
}

// Validate performs structural sanity checks. Cryptographic verification
// happens in Verify; Validate only confirms required fields are set.
func (t *Token) Validate() error {
	if t.Version != SchemaVersion {
		return errors.New("unknown token schema version")
	}
	if t.ID == "" {
		return errors.New("token id (jti) is required")
	}
	if t.Subject == "" {
		return errors.New("token subject (sub) is required")
	}
	if t.IssuedAt == 0 {
		return errors.New("token issued-at (iat) is required")
	}
	if t.RootID == "" {
		return errors.New("token root id (root_jti) is required")
	}
	if t.Tenant == "" {
		return errors.New("token tenant is required")
	}
	return nil
}

// IsRoot reports whether this token is a root (Mint output) — true when
// the per-hop ID equals the chain RootID. Attenuated children always
// fail this test.
func (t *Token) IsRoot() bool {
	return t.RootID != "" && t.RootID == t.ID
}

// CaveatCount returns the number of caveats currently on the chain.
// Used as a coarse-grained "is this token more constrained than that
// one?" signal in audit telemetry — not a security claim. The SOC
// analyst correlates (RootID, ID, CaveatCount) across audit events to
// reconstruct a delegation tree.
func (t *Token) CaveatCount() int {
	return len(t.Caveats)
}
