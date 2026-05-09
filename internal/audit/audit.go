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
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
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

	// Actor (the AI agent making the call).
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	// Resource (the tool the agent was trying to invoke).
	Tool    string   `json:"tool"`
	ArgKeys []string `json:"arg_keys,omitempty"`

	// Capability token identity (the jti). Helpful for correlating an
	// incident back to the issuance event.
	CapabilityTokenID string `json:"capability_token_id,omitempty"`
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
}

// NewEvent constructs an Event with the timestamp, event name, and
// schema version pre-populated. Callers fill in the rest.
func NewEvent(d Decision, tool string) Event {
	return Event{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		EventName:     "intentgate.tool_call",
		SchemaVersion: "1",
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
