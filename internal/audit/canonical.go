package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CanonicalForHash returns a deterministic byte representation of the
// event for hashing into the tamper-evident audit chain (Pro v2 #4,
// session 54).
//
// # What's hashed
//
// Every field that proves "the gateway said X at time Y for token Z" —
// timestamp, decision, check, reason, actor, resource, tenant, jti,
// approval lineage, step-up annotation. The fields go through a
// struct mirror with explicit json tags so the canonical form is
// stable even if [Event] gains new fields later: new fields don't
// affect existing chain hashes unless they're added to this struct.
//
// # What's NOT hashed
//
// `arg_values` (the redacted argument map) is intentionally excluded.
// It's opt-in via INTENTGATE_AUDIT_PERSIST_ARG_VALUES; including it
// would make chain hashes depend on a redaction-mode setting, and
// redacted values can contain nested maps whose encoding/json order
// IS deterministic but whose CONTENT may legitimately change across
// audit-store implementations (a column-typed JSONB round-trip can
// normalize key escapes, whitespace, number representations). Tamper
// evidence on the decision metadata is what auditors care about;
// argument-value tampering would also tamper the `tool` field or
// `arg_keys` array, which IS hashed.
//
// # Determinism
//
// encoding/json sorts map keys alphabetically (documented behavior)
// and emits struct fields in declaration order, so json.Marshal on
// the canonical mirror produces stable bytes for the same logical
// event. RFC3339Nano round-trips losslessly through Postgres
// TIMESTAMPTZ + Go time.Time, so the timestamp string survives
// store-and-reload unchanged.
func CanonicalForHash(e Event) ([]byte, error) {
	c := canonicalEvent{
		Timestamp:             e.Timestamp,
		EventName:             e.EventName,
		SchemaVersion:         e.SchemaVersion,
		Decision:              string(e.Decision),
		Check:                 string(e.Check),
		Reason:                e.Reason,
		Tenant:                e.Tenant,
		AgentID:               e.AgentID,
		SessionID:             e.SessionID,
		Tool:                  e.Tool,
		ArgKeys:               e.ArgKeys,
		CapabilityTokenID:     e.CapabilityTokenID,
		RootCapabilityTokenID: e.RootCapabilityTokenID,
		CaveatCount:           e.CaveatCount,
		PendingID:             e.PendingID,
		DecidedBy:             e.DecidedBy,
		IntentSummary:         e.IntentSummary,
		LatencyMS:             e.LatencyMS,
		RemoteIP:              e.RemoteIP,
		UpstreamStatus:        e.UpstreamStatus,
		RequiresStepUp:        e.RequiresStepUp,
		ElevationID:           e.ElevationID,
	}
	return json.Marshal(c)
}

// ComputeHash returns the chain hash for an event given the previous
// row's hash. First event in a chain passes prevHash="" (the empty
// string is part of the hashed bytes for that case, so chain verify
// re-computes the same value).
//
// Output format: lowercase hex SHA-256 (64 chars). Matches the shape
// the verify endpoint emits in error messages — easy to grep + paste
// into a SHA-256 calculator for spot-checking.
func ComputeHash(prevHash string, canonicalEventJSON []byte) string {
	h := sha256.New()
	// prevHash || canonicalEventJSON. The pipe-like delimiter is the
	// fact that prevHash is fixed-width (64 hex chars or empty); no
	// ambiguity at the boundary.
	h.Write([]byte(prevHash))
	h.Write(canonicalEventJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// HashEvent is the convenience wrapper: marshal canonical, compute
// hash. Returns the hash hex string.
func HashEvent(prevHash string, e Event) (string, error) {
	canon, err := CanonicalForHash(e)
	if err != nil {
		return "", fmt.Errorf("canonical: %w", err)
	}
	return ComputeHash(prevHash, canon), nil
}

// canonicalEvent is the explicit subset of Event hashed into the
// chain. Field order = declaration order = json.Marshal order, so
// changes here are wire-breaking and bump the chain incompatibly.
// Adding a field is fine (old chains keep verifying, new events
// hash the new field too); removing or reordering is NOT.
type canonicalEvent struct {
	Timestamp             string   `json:"ts"`
	EventName             string   `json:"event"`
	SchemaVersion         string   `json:"schema_version"`
	Decision              string   `json:"decision"`
	Check                 string   `json:"check,omitempty"`
	Reason                string   `json:"reason,omitempty"`
	Tenant                string   `json:"tenant,omitempty"`
	AgentID               string   `json:"agent_id,omitempty"`
	SessionID             string   `json:"session_id,omitempty"`
	Tool                  string   `json:"tool"`
	ArgKeys               []string `json:"arg_keys,omitempty"`
	CapabilityTokenID     string   `json:"capability_token_id,omitempty"`
	RootCapabilityTokenID string   `json:"root_capability_token_id,omitempty"`
	CaveatCount           int      `json:"caveat_count,omitempty"`
	PendingID             string   `json:"pending_id,omitempty"`
	DecidedBy             string   `json:"decided_by,omitempty"`
	IntentSummary         string   `json:"intent_summary,omitempty"`
	LatencyMS             int64    `json:"latency_ms"`
	RemoteIP              string   `json:"remote_ip,omitempty"`
	UpstreamStatus        int      `json:"upstream_status,omitempty"`
	RequiresStepUp        bool     `json:"requires_step_up,omitempty"`
	ElevationID           string   `json:"elevation_id,omitempty"`
}
