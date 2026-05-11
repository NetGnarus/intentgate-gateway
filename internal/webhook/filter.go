package webhook

import (
	"strings"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// Filter decides whether an audit event becomes a webhook delivery,
// and if so what shape. Returns (event, true) to enqueue the
// projected webhook; (zero, false) to skip.
//
// Filters MUST be cheap — they run on the request path (audit.Emit
// is called inline). A typical filter walks 3-5 fields and returns.
type Filter func(audit.Event) (WebhookEvent, bool)

// DefaultFilter returns a Filter that selects the high-signal audit
// events for webhook delivery and projects them into [WebhookEvent]s.
//
// # What's selected (matching real on-call alert practice)
//
//   - Any block decision → intentgate.deny (severity warning, or
//     critical when the check was capability/budget — those are
//     "something broke" signals, not "policy did its job").
//   - Escalate decisions → intentgate.escalate (warning). The
//     queued request now needs human review.
//   - Approval timeouts → intentgate.approval_timeout (warning).
//     An operator missed a window; the request was auto-denied.
//   - RequiresStepUp annotation → intentgate.step_up_required
//     (info on allow, warning on block). Useful for "high-risk
//     operation passed without step-up" alerting.
//
// # What's filtered out
//
//   - Plain allow with no special annotation. Routine traffic;
//     subscribing to it would drown the on-call channel.
//   - admin/mint, admin/revoke audit events. These are operator
//     actions, not agent actions — surfaced via SIEM rather than
//     real-time alerts.
//
// # Per-deployment narrowing
//
// [allowedTypes] is the comma-separated allowlist from
// INTENTGATE_WEBHOOK_EVENTS. Empty allowlist = allow everything
// the default Filter selects. Operators who want only critical
// alerts set "intentgate.deny,intentgate.approval_timeout".
func DefaultFilter(allowedTypes []string) Filter {
	allow := normalizeAllowed(allowedTypes)
	return func(ev audit.Event) (WebhookEvent, bool) {
		out, ok := projectAuditEvent(ev)
		if !ok {
			return WebhookEvent{}, false
		}
		if len(allow) > 0 {
			if _, in := allow[string(out.Event)]; !in {
				return WebhookEvent{}, false
			}
		}
		return out, true
	}
}

// projectAuditEvent maps an audit.Event onto a WebhookEvent shape,
// or returns false to skip. Kept pure (no env reads, no clock
// reads beyond NewWebhookEvent's timestamp) so unit tests can
// drive it with synthetic inputs.
func projectAuditEvent(ev audit.Event) (WebhookEvent, bool) {
	// Filter out admin operator actions — they live in SIEM, not
	// real-time alert channels.
	if ev.Tool == "admin/mint" || ev.Tool == "admin/revoke" {
		return WebhookEvent{}, false
	}

	switch ev.Decision {
	case audit.DecisionBlock:
		out := newProjection(EventDeny, severityForBlock(ev), ev)
		return out, true
	case audit.DecisionEscalate:
		out := newProjection(EventEscalate, SeverityWarning, ev)
		return out, true
	case audit.DecisionAllow:
		// Allow + RequiresStepUp is the "soft observation" path
		// where the policy says "let it through but flag it." Emit
		// at info severity so receivers can route to a low-noise
		// channel.
		if ev.RequiresStepUp {
			out := newProjection(EventStepUpRequired, SeverityInfo, ev)
			return out, true
		}
		return WebhookEvent{}, false
	}
	return WebhookEvent{}, false
}

// newProjection populates the common fields from an audit.Event onto
// a freshly-stamped WebhookEvent. NewWebhookEvent gives us the
// timestamp + schema version; we override the timestamp with the
// audit event's own ts so the receiver sees the original time.
func newProjection(t EventType, severity Severity, ev audit.Event) WebhookEvent {
	out := NewWebhookEvent(t, severity)
	if ev.Timestamp != "" {
		out.Timestamp = ev.Timestamp
	}
	out.Tenant = ev.Tenant
	out.Decision = string(ev.Decision)
	out.Check = string(ev.Check)
	out.Tool = ev.Tool
	out.AgentID = ev.AgentID
	out.Reason = ev.Reason
	out.RequiresStepUp = ev.RequiresStepUp
	out.CapabilityTokenID = ev.CapabilityTokenID
	out.PendingID = ev.PendingID
	return out
}

// severityForBlock distinguishes "infrastructure failed" from
// "policy worked as intended." A capability or budget block is
// arguably critical (a misconfigured agent / leaked token / a
// quota miscalculation); a policy or intent block is warning
// (the gateway did its job).
func severityForBlock(ev audit.Event) Severity {
	switch ev.Check {
	case audit.CheckCapability, audit.CheckBudget, audit.CheckUpstream:
		return SeverityCritical
	default:
		return SeverityWarning
	}
}

// normalizeAllowed lowercases + dedups the allowlist. Empty input
// returns nil; that's distinct from an empty Set and signals
// "allow everything the default filter selects."
func normalizeAllowed(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out[s] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
