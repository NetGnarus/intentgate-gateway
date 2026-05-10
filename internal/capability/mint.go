package capability

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// MintOptions are the inputs to Mint. Subject is required; everything
// else is optional. The minted token will be locked to Subject via an
// automatic CaveatAgentLock — that binding is part of the signed chain
// and cannot be silently swapped at the wire layer.
type MintOptions struct {
	// Issuer identifies who minted this token (default: "intentgate").
	Issuer string
	// Subject is the agent ID this token is bound to. Required.
	Subject string
	// NotBefore, if non-zero, is enforced via the iat/nbf timestamps.
	NotBefore time.Time
	// Expiry, if non-zero, is enforced as a CaveatExpiry caveat appended
	// directly after the agent-lock caveat.
	Expiry time.Time
	// Caveats are user-supplied additional restrictions. They are
	// appended after the automatic agent-lock and (optional) expiry.
	Caveats []Caveat
}

// Mint creates a new root capability token signed under masterKey.
//
// The function generates a fresh token ID (jti), prepends an
// agent-lock caveat to bind the token to its subject, optionally
// appends an expiry caveat, then appends user-provided caveats, and
// finally computes the HMAC chain signature.
func Mint(masterKey []byte, opts MintOptions) (*Token, error) {
	if opts.Subject == "" {
		return nil, errors.New("subject is required")
	}
	if len(masterKey) == 0 {
		return nil, errors.New("master key is empty")
	}

	issuer := opts.Issuer
	if issuer == "" {
		issuer = "intentgate"
	}
	id, err := newTokenID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC().Unix()
	t := &Token{
		Version: SchemaVersion,
		ID:      id,
		// Root token: the per-hop ID anchors the whole chain.
		// Attenuate later replaces ID with a fresh value but keeps
		// this RootID intact, so audit + revocation can correlate.
		RootID:   id,
		Issuer:   issuer,
		Subject:  opts.Subject,
		IssuedAt: now,
	}
	if !opts.NotBefore.IsZero() {
		t.NotBefore = opts.NotBefore.UTC().Unix()
	}

	// Lock to subject first — this caveat anchors the token's identity
	// in the signed chain.
	t.Caveats = append(t.Caveats, Caveat{
		Type:  CaveatAgentLock,
		Agent: opts.Subject,
	})
	if !opts.Expiry.IsZero() {
		t.Caveats = append(t.Caveats, Caveat{
			Type:   CaveatExpiry,
			Expiry: opts.Expiry.UTC().Unix(),
		})
	}
	t.Caveats = append(t.Caveats, opts.Caveats...)

	if err := t.Sign(masterKey); err != nil {
		return nil, err
	}
	return t, nil
}

// Attenuate appends a caveat to a parent token, producing a strictly
// more restrictive child. It does NOT need the master key — that is the
// defining property of Macaroon-style chained-HMAC delegation.
//
// The child shares the parent's JTI (and therefore RootID) — the chain
// of caveats IS the per-hop identity. Macaroons works the same way:
// per-hop revocation is layered as a discharge caveat in a future
// session, not a separate ID. For audit visibility, the gateway logs
// CaveatCount alongside JTI so a SOC analyst can correlate "events
// with same jti but different caveat counts traversed different
// delegation paths."
//
// The new signature is derived as HMAC(parent.Signature, caveatBytes).
// Because the parent's signature is itself the HMAC chain ending at
// the parent's last caveat, this hops the chain forward exactly one
// step, just as if the gateway had originally signed parent + caveat
// in one shot.
//
// Attenuate makes no semantic check that the new caveat is "narrower"
// than what the parent permitted. That is policy, not crypto. The
// cryptographic invariant is only that the chain is well-formed and
// signed under the master key transitively. The rest follows from
// caveat evaluation: if a child appends a tool_allow that's broader
// than the parent's, the gateway still rejects the call because the
// PARENT's narrower tool_allow caveat fires first.
func Attenuate(parent *Token, c Caveat) (*Token, error) {
	if parent == nil {
		return nil, errors.New("parent token is nil")
	}
	if parent.RootID == "" {
		return nil, errors.New("parent token has no root id (was it minted by gateway < v0.7?)")
	}
	parentSig, err := base64.RawURLEncoding.DecodeString(parent.Signature)
	if err != nil {
		return nil, errors.New("invalid parent signature encoding")
	}
	cb, err := c.canonicalBytes()
	if err != nil {
		return nil, err
	}

	child := *parent
	child.Caveats = append([]Caveat(nil), parent.Caveats...)
	child.Caveats = append(child.Caveats, c)
	child.Signature = base64.RawURLEncoding.EncodeToString(hmacOnce(parentSig, cb))
	return &child, nil
}

// newTokenID returns a 16-byte ID that sorts roughly by mint time:
// 4 bytes of unix seconds followed by 12 bytes of crypto/rand. The
// timestamp prefix is purely operational (sorted log lines, sane
// debugging) — it is not a security claim, since the random suffix
// provides the uniqueness guarantee.
func newTokenID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint32(b[:4], uint32(time.Now().UTC().Unix()))
	if _, err := rand.Read(b[4:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// NewMasterKey returns 32 random bytes suitable for HMAC-SHA256.
// Convenience for igctl gen-key and tests.
func NewMasterKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}
