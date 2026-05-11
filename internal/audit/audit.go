// Package audit emits structured events for every authorization
// decision the gateway makes. One event per /v1/mcp tools/call: the
// decision (allow or block), which check fired (capability, intent,
// policy, or budget), the actor (agent), the resource (tool), and the
// reason — everything the SOC analyst needs to reconstruct what the
// agent did and why the gateway responded the way it did.
//
// # Event shape
//
// The Event struct is a lightweight OCSF-lite shape: a flat JSON
// document the customer's SIEM can ingest without a custom mapper.
// Field names are lowercase_underscore so they merge cleanly into ECS
// (Elastic Common Schema), CIM (Splunk), and OCSF without a renaming
// step. Mapping to full OCSF (with category_uid, class_uid, etc.)
// can be done in a downstream parser if/when a customer needs it.
//
// # Emitters
//
// Two implementations ship in v0.1:
//
//   - [StdoutEmitter] — writes one JSON line per event to stdout.
//     The default. Operators tail the gateway's logs (or pipe through
//     vector / fluent-bit / promtail) and route into their SIEM.
//   - [NullEmitter] — drops all events. Used in tests and when audit
//     emission is intentionally disabled.
//
// Future emitters: rotated JSONL files, Kafka, OTLP. Behind the same
// [Emitter] interface so swapping is one config change.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Decision is the gateway's verdict.
type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionBlock    Decision = "block"
	DecisionEscalate Decision = "escalate"
)

// Check identifies which stage produced the decision. Empty for an
// allow that passed every stage; one of the named values otherwise.
//
// CheckUpstream is set for events about the post-pipeline forward to
// the configured upstream tool server. An allow + CheckUpstream means
// "the gateway authorized the call AND successfully forwarded it"; a
// block + CheckUpstream means "the gateway authorized the call but
// could not deliver it" (timeout, transport error, upstream 5xx).
type Check string

const (
	CheckNone       Check = ""
	CheckCapability Check = "capability"
	CheckIntent     Check = "intent"
	CheckPolicy     Check = "policy"
	CheckBudget     Check = "budget"
	CheckUpstream   Check = "upstream"
)

// Event is the on-the-wire audit record.
//
// Fields are deliberately small and stable. Add new optional fields to
// the end; do not rename existing ones — downstream SIEM mappings will
// break.
type Event struct {
	// Timestamp is RFC3339 with nanosecond precision in UTC.
	Timestamp string `json:"ts"`
	// EventName is a stable string for routing in SIEMs.
	EventName string `json:"event"`
	// Schema version of this event shape.
	SchemaVersion string `json:"schema_version"`

	Decision Decision `json:"decision"`
	Check    Check    `json:"check,omitempty"`
	Reason   string   `json:"reason,omitempty"`

	// Tenant is the trust-domain namespace this event was authorized
	// under. Read from the verified capability token; never from the
	// untrusted request. SOC analysts in multi-tenant deployments
	// filter on this field to scope a query.
	Tenant string `json:"tenant,omitempty"`

	// Actor (the AI agent making the call).
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	// Resource (the tool the agent was trying to invoke).
	Tool    string   `json:"tool"`
	ArgKeys []string `json:"arg_keys,omitempty"`
	// ArgValues is the redacted view of the call's argument values,
	// populated only when the gateway is configured with
	// INTENTGATE_AUDIT_PERSIST_ARG_VALUES=scalars (or =raw). Default
	// is to leave this empty so the audit log preserves its strict
	// keys-only privacy posture. When populated, the map mirrors
	// ArgKeys: every key in ArgValues appears in ArgKeys.
	// See audit.RedactionMode and audit.RedactArgs for the per-mode
	// rules — in particular: under "scalars" mode (the recommended
	// opt-in), numbers, booleans, and nulls survive; strings,
	// arrays-of-strings, and string-valued nested map entries are
	// replaced with null.
	ArgValues map[string]any `json:"arg_values,omitempty"`

	// Capability token identity (the jti). Helpful for correlating an
	// incident back to the issuance event.
	CapabilityTokenID string `json:"capability_token_id,omitempty"`
	// RootCapabilityTokenID is the JTI of the chain root for an
	// attenuated/delegated token. Equal to CapabilityTokenID for
	// root tokens. Lets a SOC analyst reconstruct a delegation tree
	// from the audit log: events with the same root_jti but different
	// caveat_count traversed different delegation paths.
	RootCapabilityTokenID string `json:"root_capability_token_id,omitempty"`
	// CaveatCount is the number of caveats currently bound to the
	// token's chain. Coarse-grained "is this more constrained than
	// that?" telemetry; not a security claim.
	CaveatCount int `json:"caveat_count,omitempty"`
	// PendingID correlates an "escalate" event with the eventual
	// "allow" or "block" event for the same human-approval flow.
	// SOC analyst: filter by pending_id to see the full lifecycle.
	PendingID string `json:"pending_id,omitempty"`
	// DecidedBy records the operator identity for the resolving
	// allow/block event after a human approval. Empty for direct
	// (non-escalated) decisions.
	DecidedBy string `json:"decided_by,omitempty"`
	// Intent summary captured by the extractor (one line of the user
	// prompt). Never the raw prompt — that may contain sensitive data.
	IntentSummary string `json:"intent_summary,omitempty"`

	// LatencyMS is wall-clock time the gateway spent on this request.
	LatencyMS int64 `json:"latency_ms"`

	// RemoteIP is the agent's source address as seen by the gateway.
	RemoteIP string `json:"remote_ip,omitempty"`

	// UpstreamStatus is the HTTP status code returned by the configured
	// upstream tool server, when a forward was attempted. Zero when the
	// gateway was in stub mode (no upstream configured) or when the
	// failure happened before any HTTP response (transport, timeout).
	UpstreamStatus int `json:"upstream_status,omitempty"`

	// RequiresStepUp marks the call as requiring a fresh out-of-band
	// step-up authentication factor (TOTP / WebAuthn / hardware key).
	// Populated from the Rego policy decision's `requires_step_up`
	// field. Advisory: the decision (allow/block/escalate) is still
	// authoritative for whether the call proceeded — this flag tells
	// downstream observers (the Pro console's high-risk feed, SIEM
	// dashboards) that the operation deserves extra scrutiny even
	// when it was allowed. A Rego policy enforcing strict step-up
	// returns both `allow: false` AND `requires_step_up: true`; a
	// policy observing only returns `allow: true` + `requires_step_up: true`.
	RequiresStepUp bool `json:"requires_step_up,omitempty"`
}

// NewEvent constructs an Event with the timestamp, event name, and
// schema version pre-populated. Callers fill in the rest.
//
// Schema versions:
//
//	"1" — gateway 0.1–0.6: original OCSF-lite shape.
//	"2" — gateway 0.7+: adds root_capability_token_id and caveat_count
//	      for delegation visibility. Field-add is backwards compatible
//	      for SIEM mappings — old fields unchanged, new fields
//	      omitempty when zero.
//	"3" — gateway 0.9+: adds `tenant` for multi-tenant deployments.
//	      Backwards-compatible field-add; single-tenant deployments
//	      always emit `tenant=default`.
//	"4" — gateway 1.3+: adds optional `arg_values` carrying a redacted
//	      view of the tool call's arguments. Omitempty when the operator
//	      hasn't opted in via INTENTGATE_AUDIT_PERSIST_ARG_VALUES, so
//	      v3 SIEM mappings keep working unchanged. The schema_version
//	      bump signals to dry-run consumers that ArgValues may be
//	      populated; older events still read NULL and dry-run falls
//	      back to keys-only replay.
//	"5" — gateway 1.6+: adds optional `requires_step_up` boolean
//	      sourced from the Rego policy decision. Omitempty when the
//	      policy didn't flag the call, so v4 SIEM mappings keep
//	      working unchanged. The Pro console reads this field to
//	      surface a high-risk-feed badge; SIEMs can route on it for
//	      alert pipelines.
func NewEvent(d Decision, tool string) Event {
	return Event{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		EventName:     "intentgate.tool_call",
		SchemaVersion: "5",
		Decision:      d,
		Tool:          tool,
	}
}

// Emitter is the contract for audit-event sinks.
//
// Emit is called synchronously from the request path. Implementations
// MUST NOT block: log emission is a side effect of authorization, not
// part of it. If the sink is slow (network, disk), buffer and drop —
// preferable to stalling tool-call evaluation.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// StdoutEmitter writes one JSON event per line to a configured writer
// (stdout by default). Safe for concurrent use.
type StdoutEmitter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutEmitter returns an emitter writing to os.Stdout. Use
// [NewWriterEmitter] if you need to direct events somewhere else.
func NewStdoutEmitter() *StdoutEmitter {
	return &StdoutEmitter{w: os.Stdout}
}

// NewWriterEmitter wraps an arbitrary io.Writer. Useful in tests and
// for wiring a buffered or rotating writer in production.
func NewWriterEmitter(w io.Writer) *StdoutEmitter {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutEmitter{w: w}
}

// Emit serializes the event and writes it as one line. Errors are
// silently dropped — there is nothing useful to do if audit fails
// inline, and we don't want audit to backpressure tool-call traffic.
//
// Operators worried about silent loss should pipe stdout through a
// reliable shipper (vector, fluent-bit, promtail) which has its own
// retry semantics.
func (s *StdoutEmitter) Emit(_ context.Context, e Event) {
	if s == nil {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.w.Write(line)
	_, _ = s.w.Write([]byte{'\n'})
}

// NullEmitter drops every event. Use for tests, benchmarks, and
// deployments where audit is intentionally disabled.
type NullEmitter struct{}

// NewNullEmitter returns the no-op emitter.
func NewNullEmitter() NullEmitter { return NullEmitter{} }

// Emit on NullEmitter is a no-op.
func (NullEmitter) Emit(context.Context, Event) {}

// FanOutEmitter calls Emit on each underlying emitter in order. Used
// to send the same event to multiple sinks (e.g. stdout AND a
// Postgres-backed store) without entangling either implementation
// with the other's failure modes.
//
// The fan-out is synchronous and best-effort: each underlying Emit is
// called in turn, no error is bubbled up (the [Emitter] contract is
// fire-and-forget). Underlying emitters that need async semantics
// must implement them internally — see auditstore.NewEmitter for the
// canonical async-with-drop pattern.
//
// A nil or empty FanOutEmitter is a no-op.
type FanOutEmitter struct {
	emitters []Emitter
}

// NewFanOut returns an emitter that forwards to each non-nil emitter
// in the argument list. Order is preserved.
func NewFanOut(emitters ...Emitter) *FanOutEmitter {
	out := make([]Emitter, 0, len(emitters))
	for _, e := range emitters {
		if e != nil {
			out = append(out, e)
		}
	}
	return &FanOutEmitter{emitters: out}
}

// Emit dispatches to every underlying emitter.
func (f *FanOutEmitter) Emit(ctx context.Context, e Event) {
	if f == nil {
		return
	}
	for _, em := range f.emitters {
		em.Emit(ctx, e)
	}
}

// FromTarget constructs an emitter from an INTENTGATE_AUDIT_TARGET
// string. Recognized targets:
//
//   - "stdout" or empty — [StdoutEmitter] writing to os.Stdout
//   - "none" or "off"   — [NullEmitter]
//
// Unknown targets return an error so misconfiguration fails at
// startup rather than at audit time.
func FromTarget(target string) (Emitter, string, error) {
	switch target {
	case "", "stdout":
		return NewStdoutEmitter(), "stdout", nil
	case "none", "off":
		return NewNullEmitter(), "none", nil
	default:
		return nil, "", fmt.Errorf("unknown audit target %q (want stdout|none)", target)
	}
}
