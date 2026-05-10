// Package revocation provides storage and lookup for revoked
// capability tokens.
//
// # Threat model
//
// Capability tokens are stateless: they're verified by HMAC chain
// against the master key and evaluated against their caveats. Once
// minted, a token is valid until its expiry caveat fires.
//
// Revocation is the operator's emergency stop: a way to invalidate a
// token before its natural expiry without rotating the master key
// (which would invalidate every other outstanding token too). Use
// cases: leaked token, agent compromise, "I made a mistake minting
// that 10-year-TTL token", auditor request.
//
// # Storage
//
// Two implementations ship in this package:
//
//   - [MemoryStore] — in-process map. Single-replica only; revocations
//     are lost on gateway restart. Fine for dev, tests, single-node
//     installs that accept the trade-off.
//   - [PostgresStore] — durable, queryable, multi-replica safe. The
//     production default once a Postgres URL is configured. Schema is
//     a single table with the JTI as primary key plus revoked-at and
//     reason columns; an embedded SQL migration runs at startup.
//
// # Hot path
//
// IsRevoked is called on every authorized tool call. The Postgres
// implementation issues one indexed primary-key lookup per request;
// at typical agent traffic levels (<100 RPS per gateway) that's well
// within Postgres's comfort zone. If a deployment outgrows it, the
// natural next step is a write-through cache in front of the store —
// out of scope for v1.
//
// # Tenancy
//
// Revocations are tenant-scoped on both write and read paths
// (gateway 1.0.1+). A per-tenant admin's revocation only affects
// tokens issued under their tenant; a superadmin revocation
// (tenant="") still applies globally. This closes the cross-tenant
// denial-of-service vector that existed in 1.0, where any per-tenant
// admin could revoke any JTI and the tenant-blind hot path would
// honor it across every tenant.
package revocation

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by stores that need to distinguish "no
// matching record" from other errors. IsRevoked translates this to a
// false return.
var ErrNotFound = errors.New("revocation: not found")

// RevokedToken is the on-the-wire and in-store record of a revocation.
type RevokedToken struct {
	// JTI is the capability token's ID (the "jti" field on a Token).
	JTI string `json:"jti"`
	// RevokedAt is when the revocation was recorded, in UTC.
	RevokedAt time.Time `json:"revoked_at"`
	// Reason is operator-supplied context. May be empty.
	Reason string `json:"reason,omitempty"`
	// Tenant scopes the revocation. Per-tenant admins set this on
	// revoke; superadmin-revoked rows carry empty tenant ("") which
	// is the canonical "applies to every tenant" marker on the hot
	// path. Per-tenant list queries filter on this field; superadmin
	// queries see every row.
	Tenant string `json:"tenant,omitempty"`
}

// Store is the contract every revocation backend implements.
//
// Implementations MUST be safe for concurrent use: IsRevoked is on the
// gateway's hot path and called under any number of concurrent
// in-flight requests.
type Store interface {
	// IsRevoked returns true if the JTI has been revoked for the
	// caller's tenant. Matches a row whose tenant is either tenant
	// (per-tenant revocation) or "" (superadmin revocation; applies
	// globally). Pass the verified token's tenant — never a string
	// derived from request input that hasn't been crypto-checked, or
	// the tenancy guarantee evaporates.
	//
	// Network or disk errors are surfaced; a non-nil error from
	// IsRevoked means the caller could not determine the answer.
	// Production callers should fail closed (treat error as revoked)
	// — a partial outage of the revocation store should not become a
	// quiet authorization bypass.
	IsRevoked(ctx context.Context, jti, tenant string) (bool, error)

	// Revoke records a revocation. Idempotent: revoking an already-
	// revoked (jti, tenant) pair is not an error. Reason may be
	// empty. Tenant participates in the storage key, so different
	// tenants' revocations of the same JTI are independent rows that
	// don't overwrite each other — the cross-tenant DoS vector that
	// existed in 1.0 is closed at this layer.
	Revoke(ctx context.Context, jti, reason, tenant string) error

	// List returns recent revocations, most-recent first. limit caps
	// the page size; offset enables pagination. Used by the admin UI;
	// not on the request path. Tenant scopes the result — empty
	// returns ALL rows (superadmin view); a non-empty tenant filters
	// to that tenant's revocations only. Rows whose tenant is NULL
	// (revocations recorded before multi-tenant) are visible only to
	// the superadmin (empty filter).
	List(ctx context.Context, tenant string, limit, offset int) ([]RevokedToken, error)
}
