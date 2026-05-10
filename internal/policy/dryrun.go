// Dry-run evaluation of a candidate Rego policy against historical
// audit events. Powers the /v1/admin/policies/dry-run admin endpoint
// and the console-pro AI-assisted policy authoring view: an operator
// (or AI generator) drafts a new policy, the gateway replays it
// against the last N hours of real traffic, and the response surfaces
// which past decisions would change.
//
// # What gets evaluated
//
// Each audit event is converted into a [policy.Input] using the same
// shape the live policy check sees:
//
//   - tool, agent_id, session_id     — copied verbatim
//   - intent.summary                 — copied verbatim (other intent fields
//                                      aren't persisted on audit events)
//   - args                           — keys reconstructed from
//                                      audit.Event.ArgKeys; **values are
//                                      nil** because we deliberately don't
//                                      persist them (privacy).
//
// The `nil`-value gap is the headline caveat: a Rego rule that depends
// on an argument *value* (`input.args.amount_eur > 10000`) can't be
// faithfully replayed and will typically evaluate as a runtime error
// or fall through to the default rule. We surface that in
// DryRunResult.PolicyError and DryRunResult.Warnings rather than
// pretending the dry-run is exact. A future enhancement may capture
// redacted/hashed argument values on the audit event so threshold
// rules can replay; until then, the dry-run is exact for rules keyed
// on tool name, agent identity, arg-key presence, and intent summary,
// and approximate for value-based rules.
//
// # What "changed" means
//
// The audit event's `decision` is the *final* outcome — which may have
// been produced by an earlier check (capability, intent, budget,
// upstream) before policy ran. So a candidate policy result of
// `block` for an event whose original decision was `block` at the
// `capability` stage isn't really a "change" — the existing pipeline
// already blocks it. We report the comparison honestly and tag each
// sample with the event's original `check` so the operator can filter
// out short-circuited rows in the UI.
//
// # Performance
//
// The Rego query is prepared once and reused for every event. With
// the embedded OPA engine, evaluation is ~tens of microseconds per
// call; a 100k-event window completes in low seconds. We don't
// parallelize today; the admin endpoint clamps the input set to a
// configurable cap (default 10000, max 100000) so worst case stays
// bounded.

package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// DryRunOptions tunes a [DryRun] call.
type DryRunOptions struct {
	// MaxSamples caps the number of diff samples returned in the
	// response. Zero falls back to DefaultMaxSamples. The summary
	// counters always reflect the full input set; only the sample
	// list is truncated.
	MaxSamples int
}

// DefaultMaxSamples is the default cap for DryRunOptions.MaxSamples.
// 100 is enough for an operator to spot patterns without bloating the
// HTTP response or the console table.
const DefaultMaxSamples = 100

// DryRunDecision is the simplified verdict returned for each evaluated
// event. Mirrors [audit.Decision] string values so the console can
// compare candidate vs original without an extra mapping step.
type DryRunDecision string

const (
	DryRunAllow    DryRunDecision = "allow"
	DryRunBlock    DryRunDecision = "block"
	DryRunEscalate DryRunDecision = "escalate"
	// DryRunError marks an event whose evaluation threw a runtime
	// error (most commonly: the policy references an argument value
	// that isn't present in the replayed input). Surfaced separately
	// from block so the operator can see "I need to refine my rule"
	// signal rather than "my rule blocks N requests" noise.
	DryRunError DryRunDecision = "error"
)

// DryRunSample is one event with its candidate-policy outcome.
//
// Returned in DryRunResult.Samples for events whose candidate decision
// differs from the original audit decision, ordered most-recent first.
// Args values are never included — the policy only ever sees arg keys
// during dry-run, so there are no values to expose here either.
type DryRunSample struct {
	Timestamp        string         `json:"ts"`
	Tool             string         `json:"tool"`
	AgentID          string         `json:"agent_id,omitempty"`
	Tenant           string         `json:"tenant,omitempty"`
	OriginalDecision audit.Decision `json:"original_decision"`
	OriginalCheck    audit.Check    `json:"original_check,omitempty"`
	OriginalReason   string         `json:"original_reason,omitempty"`
	CandidateOutcome DryRunDecision `json:"candidate_decision"`
	CandidateReason  string         `json:"candidate_reason,omitempty"`
	// CandidateError carries the Rego runtime error string for
	// CandidateOutcome == DryRunError. Empty otherwise.
	CandidateError string `json:"candidate_error,omitempty"`
	// ArgKeys is the keys-only view of the original call's arguments,
	// the same information the policy saw during evaluation.
	ArgKeys []string `json:"arg_keys,omitempty"`
}

// DryRunSummary is the aggregate counters across every evaluated event.
//
// EventsEvaluated == sum of CandidateAllow + CandidateBlock +
// CandidateEscalate + PolicyError. Changes is the cross-tabulation:
// AllowToBlock counts events whose original decision was allow and
// whose candidate decision was block, and so on.
type DryRunSummary struct {
	EventsEvaluated int `json:"events_evaluated"`

	// Candidate distribution.
	CandidateAllow    int `json:"would_allow"`
	CandidateBlock    int `json:"would_block"`
	CandidateEscalate int `json:"would_escalate"`
	PolicyError       int `json:"policy_error"`

	// Cross-tabulation of original × candidate. "no change" not
	// listed; it's EventsEvaluated minus the sum of the rest.
	AllowToBlock    int `json:"allow_to_block"`
	AllowToEscalate int `json:"allow_to_escalate"`
	BlockToAllow    int `json:"block_to_allow"`
	BlockToEscalate int `json:"block_to_escalate"`
	EscalateToAllow int `json:"escalate_to_allow"`
	EscalateToBlock int `json:"escalate_to_block"`
}

// DryRunResult is the response shape returned by [DryRun].
type DryRunResult struct {
	Summary  DryRunSummary  `json:"summary"`
	Samples  []DryRunSample `json:"samples"`
	Warnings []string       `json:"warnings,omitempty"`
}

// DryRun compiles the supplied Rego source once, evaluates it against
// each event in turn, and returns the aggregated counters plus a
// bounded sample of events whose candidate decision differs from the
// original.
//
// regoSource is the full policy module — package declaration + rules,
// the same string you'd hand [NewEngine]. A compile error returns
// (zero result, error) so callers can render the message back to the
// operator without crashing.
//
// events is the historical traffic to replay. Pass them in any
// order; the result orders samples most-recent-first by Timestamp.
func DryRun(ctx context.Context, regoSource string, events []audit.Event, opts DryRunOptions) (DryRunResult, error) {
	if strings.TrimSpace(regoSource) == "" {
		return DryRunResult{}, errors.New("policy: dry-run requires a non-empty Rego source")
	}

	eng, err := NewEngine(ctx, regoSource)
	if err != nil {
		return DryRunResult{}, fmt.Errorf("policy: compile candidate: %w", err)
	}

	maxSamples := opts.MaxSamples
	if maxSamples <= 0 {
		maxSamples = DefaultMaxSamples
	}

	out := DryRunResult{
		Samples: make([]DryRunSample, 0, maxSamples),
	}

	// Static pre-scan: does the candidate policy reference argument
	// VALUES (input.args.<key>)? If so, those rules will silently fail
	// to match during dry-run — OPA treats `to_number(nil) > N` etc.
	// as undefined, which makes the rule no-op rather than error out.
	// That's a footgun: a threshold rule appears to never fire, which
	// looks like "policy is safe to deploy" when really it's "I
	// couldn't test this rule." We warn unconditionally when any
	// such access is present. Real runtime errors (division by zero,
	// builtin misuse) still surface per-event as policy_error.
	sourceReferencesArgValues := argValueAccessRe.MatchString(regoSource)

	for _, ev := range events {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}

		input := inputFromEvent(ev)
		var candidate DryRunDecision
		var candidateReason, candidateErr string

		decision, evalErr := eng.Evaluate(ctx, input)
		switch {
		case evalErr != nil:
			candidate = DryRunError
			candidateErr = evalErr.Error()
			out.Summary.PolicyError++
		case decision.Escalate:
			candidate = DryRunEscalate
			candidateReason = decision.Reason
			out.Summary.CandidateEscalate++
		case decision.Allow:
			candidate = DryRunAllow
			candidateReason = decision.Reason
			out.Summary.CandidateAllow++
		default:
			candidate = DryRunBlock
			candidateReason = decision.Reason
			out.Summary.CandidateBlock++
		}

		out.Summary.EventsEvaluated++
		bumpCrossTab(&out.Summary, ev.Decision, candidate)

		if !candidatesMatch(ev.Decision, candidate) && len(out.Samples) < maxSamples {
			out.Samples = append(out.Samples, DryRunSample{
				Timestamp:        ev.Timestamp,
				Tool:             ev.Tool,
				AgentID:          ev.AgentID,
				Tenant:           ev.Tenant,
				OriginalDecision: ev.Decision,
				OriginalCheck:    ev.Check,
				OriginalReason:   ev.Reason,
				CandidateOutcome: candidate,
				CandidateReason:  candidateReason,
				CandidateError:   candidateErr,
				ArgKeys:          append([]string(nil), ev.ArgKeys...),
			})
		}
	}

	// Sort samples most-recent first. Timestamps are RFC3339Nano
	// strings; sortable lexically since the format is fixed-width and
	// always UTC.
	sortSamplesNewestFirst(out.Samples)

	if sourceReferencesArgValues {
		out.Warnings = append(out.Warnings,
			"the candidate policy references argument values (input.args.<key>). "+
				"Audit events store argument keys but not values (by design, to avoid persisting PII), "+
				"so OPA treats those references as undefined during replay and the rule silently no-ops "+
				"— rather than firing or producing an error. Value-dependent rules (e.g. amount thresholds) "+
				"will work correctly on live traffic; you just cannot validate them via dry-run today.")
	}
	if out.Summary.EventsEvaluated == 0 {
		out.Warnings = append(out.Warnings,
			"no audit events matched the dry-run window. Either widen the time range or "+
				"confirm INTENTGATE_AUDIT_PERSIST is enabled on the gateway.")
	}

	return out, nil
}

// inputFromEvent rebuilds a [policy.Input] from the persisted fields
// of an audit event. ArgKeys → args[key] = nil (keys present, values
// unknown). Intent gets a summary-only fill (the other intent fields
// aren't on the audit event today). Capability subject/issuer aren't
// on the audit event either; we omit them.
func inputFromEvent(e audit.Event) Input {
	args := make(map[string]any, len(e.ArgKeys))
	for _, k := range e.ArgKeys {
		args[k] = nil
	}
	var intent *InputIntent
	if e.IntentSummary != "" {
		intent = &InputIntent{Summary: e.IntentSummary}
	}
	return Input{
		Tool:      e.Tool,
		Args:      args,
		AgentID:   e.AgentID,
		SessionID: e.SessionID,
		Intent:    intent,
	}
}

// candidatesMatch returns true when the candidate decision lines up
// with the event's original audit decision. DryRunError never matches
// (it's a per-event evaluation failure, never "the same as" any
// real decision).
func candidatesMatch(orig audit.Decision, cand DryRunDecision) bool {
	if cand == DryRunError {
		return false
	}
	return string(orig) == string(cand)
}

// bumpCrossTab increments the right counter in the original×candidate
// cross-tabulation. Same-outcome cells aren't tracked; they're
// EventsEvaluated minus the sum of the rest.
func bumpCrossTab(s *DryRunSummary, orig audit.Decision, cand DryRunDecision) {
	if cand == DryRunError {
		return
	}
	if string(orig) == string(cand) {
		return
	}
	switch orig {
	case audit.DecisionAllow:
		switch cand {
		case DryRunBlock:
			s.AllowToBlock++
		case DryRunEscalate:
			s.AllowToEscalate++
		}
	case audit.DecisionBlock:
		switch cand {
		case DryRunAllow:
			s.BlockToAllow++
		case DryRunEscalate:
			s.BlockToEscalate++
		}
	case audit.DecisionEscalate:
		switch cand {
		case DryRunAllow:
			s.EscalateToAllow++
		case DryRunBlock:
			s.EscalateToBlock++
		}
	}
}

// sortSamplesNewestFirst orders by RFC3339Nano timestamp descending.
// Insertion sort is fine — Samples is bounded at MaxSamples (default
// 100) so the O(n²) worst case is trivial.
func sortSamplesNewestFirst(s []DryRunSample) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1].Timestamp < s[j].Timestamp; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// argValueAccessRe matches a reference to an argument VALUE in the
// candidate policy source: input.args.<identifier>. We use this as a
// static pre-flight signal because OPA's runtime treats references to
// nil values as undefined rather than as errors, so the only reliable
// way to tell the operator "you have a value-threshold rule and dry-
// run cannot validate it" is to inspect the source itself.
//
// Bracket indexing (input.args["amount_eur"]) is rare in practice and
// not matched; nothing breaks if we miss it — the operator just won't
// see the warning. False positives are fine: warning when there's
// nothing to worry about is much better than silence when there is.
var argValueAccessRe = regexp.MustCompile(`input\.args\.\w+`)
