// Package approvals manages the queue of pending high-risk tool calls
// awaiting human decision.
//
// # Why
//
// Some tool calls are too high-stakes to autopilot. The mechanism is
// general — anything a Rego rule can match can escalate. The gateway
// should not block (the call may be legitimate) nor allow (no human
// reviewed it). It pauses, surfaces the request to a human operator,
// and resumes on the human's decision.
//
// Common escalation patterns the same code supports:
//
//   - financial: `transfer_funds`, `refund`, `purchase` over a threshold
//   - communications: `send_email` to external domains, `post`, `publish`
//   - data destruction: `delete_user`, `drop_table`, anything `delete_*`
//   - access changes: `grant_role`, `share_document`, `make_public`,
//     `rotate_credentials`
//   - infrastructure: `deploy_*`, `terraform_apply`, `restart_service` in prod
//   - bulk reads: `query_database` with no LIMIT (data-exfiltration shape)
//   - identity: `create_user`, `reset_password`, `disable_mfa`, `impersonate`
//   - off-hours: any tool from a finance agent at 03:00 UTC
//   - sensitive content: any call where intent extractor sees PII / PHI
//
// The pitch demo's `transfer_funds > 1,000 EUR` example is one row of
// that table, not the limit of the feature.
//
// This package owns the pause-and-resume state: a queue of pending
// requests, a Wait primitive that blocks the request handler until
// decision (or timeout), and a Decide primitive the admin endpoint
// calls when an operator clicks Approve / Reject in the console.
//
// # Storage
//
// Two implementations ship in this package:
//
//   - [MemoryStore] — in-process map plus a fan-out of channels for
//     Wait. Single-replica only; pending requests are lost on gateway
//     restart. Fine for dev and single-node installs that accept the
//     trade-off.
//   - [PostgresStore] — durable, queryable, multi-replica safe. The
//     production default once a Postgres URL is configured. A
//     LISTEN/NOTIFY pair across replicas wakes a Wait blocked on one
//     replica when Decide is called on another. An embedded SQL
//     migration runs at startup.
//
// # Failure semantics
//
// A timed-out Wait reports the timeout reason and the gateway returns
// "approval window expired" to the agent. The pending row stays in
// the store with status=`timeout` so SOC sees the trail. An operator
// who decides AFTER the timeout gets a 409 Conflict — the call is
// already over.
package approvals

import (
	"context"
	"errors"
	"time"
)

// Status is the lifecycle state of a pending request.
type Status string

const (
	// StatusPending: enqueued, awaiting human decision.
	StatusPending Status = "pending"
	// StatusApproved: operator clicked Approve. The original request
	// is allowed to continue through the rest of the pipeline.
	StatusApproved Status = "approved"
	// StatusRejected: operator clicked Reject. The original request
	// returns "rejected by reviewer" to the agent.
	StatusRejected Status = "rejected"
	// StatusTimeout: nobody decided before the gateway's wait
	// deadline. The original request returns "approval window
	// expired" to the agent.
	StatusTimeout Status = "timeout"
)

// ErrAlreadyDecided is returned when [Store.Decide] is called on a
// pending_id that has already moved past StatusPending. Admin
// endpoint surfaces this as 409 Conflict.
var ErrAlreadyDecided = errors.New("approvals: already decided")

// ErrNotFound is returned when a pending_id has no record. Admin
// endpoint surfaces this as 404.
var ErrNotFound = errors.New("approvals: not found")

// PendingRequest is the on-the-wire and in-store record of a
// pause-pending tool call.
//
// Sensitive fields are intentional. Args is a verbatim copy of the
// tool-call arguments — this lets the operator review the actual
// payload before approving. Treat the whole row as sensitive at the
// storage layer (encrypted-at-rest by Postgres TDE / cloud disk
// encryption) and on the wire (admin TLS).
type PendingRequest struct {
	// PendingID is the queue's primary key. Time-prefixed random;
	// safe to expose in URLs.
	PendingID string `json:"pending_id"`

	// CapabilityTokenID and RootCapabilityTokenID correlate with the
	// audit event for this same request.
	CapabilityTokenID     string `json:"capability_token_id,omitempty"`
	RootCapabilityTokenID string `json:"root_capability_token_id,omitempty"`

	// AgentID and Tool identify the actor and resource.
	AgentID string `json:"agent_id"`
	Tool    string `json:"tool"`

	// Args is the verbatim tool-call arguments. JSONB on Postgres so
	// the operator can read structured data, not a blob.
	Args map[string]any `json:"args,omitempty"`

	// IntentSummary is the one-line intent extracted from the user's
	// prompt (when an extractor is wired). Lets the reviewer compare
	// "what the user asked for" with "what the agent actually wants
	// to do."
	IntentSummary string `json:"intent_summary,omitempty"`

	// Reason is the policy-supplied human-readable reason for the
	// escalation. Examples: "high_risk_payment (above 1,000 EUR)",
	// "external_email_recipient", "bulk_delete (>100 rows)",
	// "off_hours_finance_agent". Whatever string the Rego policy set
	// in `decision.reason`.
	Reason string `json:"reason"`

	// Lifecycle.
	Status     Status     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	DecidedBy  string     `json:"decided_by,omitempty"`
	DecideNote string     `json:"decide_note,omitempty"`
}

// Decision is the operator's verdict, applied via [Store.Decide].
type Decision struct {
	// Status MUST be StatusApproved or StatusRejected.
	Status Status
	// DecidedBy is the operator identity (admin token holder name,
	// console-pro user email, or "unknown").
	DecidedBy string
	// Note is operator-supplied free text recorded in the audit log.
	Note string
}

// Store is the contract every approvals backend implements.
//
// All methods MUST be safe for concurrent use. Wait is on the request
// hot path — it must not hold mutexes longer than necessary, and a
// concurrent Decide must wake it promptly.
type Store interface {
	// Enqueue records a new pending request and returns the inserted
	// row (with PendingID, CreatedAt, Status=pending populated).
	Enqueue(ctx context.Context, req PendingRequest) (PendingRequest, error)

	// Wait blocks until the pending row's status leaves
	// StatusPending. Returns the final row. If ctx is cancelled
	// before a decision (gateway timeout), Wait records
	// StatusTimeout on the row and returns it — the caller emits the
	// final audit event.
	Wait(ctx context.Context, pendingID string) (PendingRequest, error)

	// Decide records an operator's verdict. Idempotency: a second
	// Decide on the same id returns ErrAlreadyDecided without
	// mutating state. Non-pending rows return ErrAlreadyDecided.
	// Wakes any Wait blocked on this id.
	Decide(ctx context.Context, pendingID string, dec Decision) (PendingRequest, error)

	// Get returns a single row. Useful for the admin endpoint's
	// detail view; not on the hot path.
	Get(ctx context.Context, pendingID string) (PendingRequest, error)

	// List returns rows filtered by status, most-recent first.
	// Empty status filter returns all rows.
	List(ctx context.Context, filter ListFilter) ([]PendingRequest, error)

	// Close releases resources. Calling other methods after Close is
	// undefined.
	Close() error
}

// ListFilter narrows [Store.List] results.
type ListFilter struct {
	Status Status
	Limit  int
	Offset int
}
