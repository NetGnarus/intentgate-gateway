// Package auditstore provides durable storage and query for the audit
// events the gateway emits on every authorization decision.
//
// # Why a store
//
// The base [audit.StdoutEmitter] writes one JSON line per decision and
// hands the durability problem to whatever ships logs off the
// container (vector / fluent-bit / promtail / Loki / Datadog Agent).
// That's the right default — it keeps the gateway small and lets the
// operator pick the SIEM they already run.
//
// But two product surfaces need a queryable view that doesn't depend
// on the operator's SIEM:
//
//   - The OSS audit-log viewer in `intentgate-console` — operators
//     want a "what did the gateway do in the last hour?" page without
//     a Loki round trip.
//   - The Pro compliance pack — auditors want "show me decisions for
//     agent X between dates Y and Z". Today the operator hand-uploads
//     ndjson; a stored audit log lets the console answer this directly.
//
// Both want SQL-grade filtering with low operational ceremony, and we
// already run Postgres for [revocation]. Reusing it costs one table
// and one optional emitter; replicas keep their existing scrape
// behavior.
//
// # Storage
//
// Two implementations ship in this package:
//
//   - [MemoryStore] — bounded in-process ring buffer. Single-replica
//     only; events are lost on gateway restart. Fine for tests, dev,
//     and small single-node installs that accept the trade-off.
//   - [PostgresStore] — durable, queryable, multi-replica safe. The
//     production default once a Postgres URL is configured AND audit
//     persistence is opted into. Schema is a single table mirroring
//     [audit.Event] with indexes on the columns the console filters
//     by; an embedded SQL migration runs at startup.
//
// # Hot path
//
// Inserts come from an async emitter ([NewPostgresEmitter]) so DB
// latency does not block the gateway's request path. The buffer drops
// on overflow rather than blocking; the [audit.Emitter] contract is
// "MUST NOT block, buffer and drop if slow" and we honor it. Query is
// off the hot path entirely (admin UI only).
package auditstore

import (
	"context"
	"errors"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// ErrClosed is returned by an emitter that has been shut down.
var ErrClosed = errors.New("auditstore: closed")

// QueryFilter narrows the events returned by [Store.Query]. All fields
// are optional; the zero value matches everything (subject to Limit).
type QueryFilter struct {
	// From and To are inclusive bounds on the event timestamp. Either
	// or both may be the zero value.
	From time.Time
	To   time.Time
	// AgentID, Tool, Decision, Check, CapabilityTokenID, Tenant are
	// equality filters when non-empty.
	AgentID           string
	Tool              string
	Decision          string
	Check             string
	CapabilityTokenID string
	// Tenant scopes the query to a single trust domain. Empty matches
	// all tenants (admin / superuser view); set to "default" for
	// single-tenant deployments that opt into explicit filtering.
	Tenant string
	// Limit caps the page size. Implementations MUST cap further at
	// their own internal maximum (1000) to avoid pathological queries.
	// Zero is treated as the implementation default.
	Limit int
	// Offset enables pagination. Zero is the start of the result set.
	Offset int
}

// Store is the contract every audit-event backend implements.
//
// Implementations MUST be safe for concurrent use: Insert is called
// under any number of concurrent in-flight requests via the async
// emitter, and Query may be called concurrently from the admin UI.
type Store interface {
	// Insert records one audit event. Idempotency is not promised —
	// the audit log captures every emission, including duplicates that
	// might arise from a retry path. Implementations should fail fast
	// on a network error rather than retrying internally; the async
	// emitter handles retry / drop semantics one layer up.
	Insert(ctx context.Context, e audit.Event) error

	// Query returns events matching the filter, most-recent first.
	// Used by the admin /v1/admin/audit endpoint; not on the request
	// path. Implementations cap the Limit at 1000 internally.
	Query(ctx context.Context, f QueryFilter) ([]audit.Event, error)

	// Count returns the number of events matching the filter, ignoring
	// Limit / Offset. Used for paginated UIs that want a total count.
	// Implementations may return -1 if the count is too expensive to
	// compute cheaply (the UI should treat -1 as "unknown").
	Count(ctx context.Context, f QueryFilter) (int64, error)

	// Close releases resources. Calling Insert / Query after Close is
	// undefined; callers should drain any async emitter first.
	Close() error
}
