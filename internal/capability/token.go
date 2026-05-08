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
const SchemaVersion = 1

// Token is the on-wire and in-memory representation of a capability.
//
// Field order matters for canonical serialization: the JSON encoder
// emits struct fields in declaration order, and the HMAC chain commits
// to those bytes. Reordering fields will silently invalidate every
// pre-existing token.
type Token struct {
	Version   int      `json:"v"`
	ID        string   `json:"jti"`
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	Caveats   []Caveat `json:"cav,omitempty"`
	Signature string   `json:"sig"`
}

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
)

// Caveat is a structured restriction recorded in a token's chain.
//
// Caveats use a tagged-union JSON shape rather than per-type Go types
// because (a) the wire format must round-trip cleanly through plain
// JSON and (b) the canonical bytes input to the HMAC chain need to be
// stable and inspectable. A future migration to typed caveats is
// possible without changing the chain construction.
type Caveat struct {
	Type   string   `json:"t"`
	Tools  []string `json:"tools,omitempty"`
	Agent  string   `json:"agent,omitempty"`
	Expiry int64    `json:"exp,omitempty"`
}

// canonicalPayload returns the bytes that seed the HMAC chain. It
// excludes Caveats and Signature; those are absorbed by the chain.
func (t *Token) canonicalPayload() ([]byte, error) {
	body := struct {
		Version   int    `json:"v"`
		ID        string `json:"jti"`
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		IssuedAt  int64  `json:"iat"`
		NotBefore int64  `json:"nbf,omitempty"`
	}{
		Version:   t.Version,
		ID:        t.ID,
		Issuer:    t.Issuer,
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
	return nil
}
