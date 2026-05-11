// Package webhook ships high-signal audit events to operator-
// configured HTTP endpoints. The primary consumers in v1 are the
// Pro console's notification channels (Slack, Microsoft Teams,
// PagerDuty) but the wire shape is intentionally generic — any
// receiver that can speak HTTP + verify an HMAC signature works.
//
// # Why a peer of the SIEM emitters
//
// The SIEM emitters (internal/siem) batch events and POST them
// periodically to a single configured destination per integration.
// Webhooks have different semantics:
//
//   - Per-event delivery: a "policy deny on transfer_funds" alert
//     is one Slack message, not a batched payload. Receivers expect
//     one event per POST.
//   - Filtered subset: most audit events are routine and don't
//     warrant an alert. We project audit.Event → WebhookEvent only
//     for the high-signal cases (deny / escalate / requires_step_up
//     / approval-timeout / policy-promote).
//   - HMAC signing: receivers verify the gateway sent the message
//     (especially important when console-pro fans out to operator-
//     configured channels). GitHub-style sha256= header on the body.
//   - Retry with exponential backoff: Slack webhooks can 429; we
//     retry up to MaxRetries before logging the drop.
//
// # Failure isolation
//
// Like the SIEM emitters, the webhook emitter has its own bounded
// buffer + worker. A slow or misconfigured receiver drops on
// overflow, never blocks the request path, and never affects the
// other emitters in the audit fan-out. The Emit contract is
// fire-and-forget; backpressure manifests as DroppedCount in the
// admin /v1/admin/integrations response, not as latency.
package webhook

import (
	"context"
	"time"
)

// SchemaVersion is the wire-format version of [WebhookEvent]. The
// console renders v1; v2 etc. would add optional fields with
// omitempty so old receivers keep working.
const SchemaVersion = "1"

// Severity classifies the operational urgency of a webhook event.
// Receivers route by severity: a Slack channel might subscribe to
// "warning+", a PagerDuty integration to "critical" only.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// EventType is the stable identifier the console + receivers use
// to route + format messages. New types should be added here AND
// in [DefaultFilter] (which decides which audit decisions map to
// which event).
type EventType string

const (
	// EventDeny: any check returned a block decision.
	EventDeny EventType = "intentgate.deny"
	// EventEscalate: a policy returned escalate=true; the request
	// is waiting for human approval in the queue.
	EventEscalate EventType = "intentgate.escalate"
	// EventApprovalTimeout: a queued request timed out without an
	// operator decision.
	EventApprovalTimeout EventType = "intentgate.approval_timeout"
	// EventStepUpRequired: the policy decision flagged the call as
	// requiring a fresh out-of-band factor (audit.RequiresStepUp).
	// Useful as an early-warning signal even when the call was
	// allowed — the audit pipeline can surface "high-risk operation
	// passed without step-up" alerts.
	EventStepUpRequired EventType = "intentgate.step_up_required"
)

// WebhookEvent is the payload POSTed to receivers. Fields are
// deliberately a small subset of audit.Event — what an alert
// payload actually needs, not the full SOC record. SIEM mappings
// continue to consume audit.Event directly.
//
// JSON keys are lowercase_underscore so receivers can route on
// them without a renaming step.
type WebhookEvent struct {
	// Event is the [EventType] string.
	Event EventType `json:"event"`
	// SchemaVersion of the wire format.
	SchemaVersion string `json:"schema_version"`
	// Timestamp in RFC3339Nano UTC.
	Timestamp string `json:"timestamp"`
	// Severity routes the event to the right channel.
	Severity Severity `json:"severity"`
	// Tenant is the trust-domain namespace this event was authorized
	// under. Receivers in a multi-tenant deployment filter on this
	// to route per-tenant.
	Tenant string `json:"tenant,omitempty"`
	// Decision is "allow" / "block" / "escalate" — same vocabulary
	// as audit.Decision.
	Decision string `json:"decision"`
	// Check is which stage produced the decision: capability /
	// intent / policy / budget / upstream / empty.
	Check string `json:"check,omitempty"`
	// Tool the agent was trying to invoke.
	Tool string `json:"tool"`
	// AgentID from the verified capability token.
	AgentID string `json:"agent_id,omitempty"`
	// Reason is the operator-readable explanation.
	Reason string `json:"reason,omitempty"`
	// RequiresStepUp mirrors the audit-event flag — set when the
	// Rego policy stage said the call needed a fresh out-of-band
	// factor, regardless of whether the call was allowed.
	RequiresStepUp bool `json:"requires_step_up,omitempty"`
	// CapabilityTokenID lets an operator correlate the alert with
	// the audit log entry (and revoke the token if needed).
	CapabilityTokenID string `json:"capability_token_id,omitempty"`
	// PendingID correlates an escalate event with the eventual
	// approve/reject; set on intentgate.escalate and intentgate
	// .approval_timeout events.
	PendingID string `json:"pending_id,omitempty"`
}

// NewWebhookEvent constructs an event with the schema version + UTC
// timestamp pre-populated. Callers fill in the rest.
func NewWebhookEvent(t EventType, severity Severity) WebhookEvent {
	return WebhookEvent{
		Event:         t,
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Severity:      severity,
	}
}

// Sink delivers a single WebhookEvent to its destination. Returns
// an error to signal "the worker should record this as a failure";
// the worker is responsible for retry / dead-letter — Sink itself
// does NOT retry.
//
// Implementations MUST NOT block indefinitely; they should respect
// ctx.Deadline() and return promptly on cancellation.
type Sink interface {
	Deliver(ctx context.Context, ev WebhookEvent) error
}
