package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// regoBlockTransfer is a tiny policy that blocks transfer_funds and
// allows everything else — purely keyed on tool name so it dry-runs
// faithfully against keys-only audit events.
const regoBlockTransfer = `package intentgate.policy
import rego.v1

default decision := {"allow": true, "reason": "default-allow"}

decision := {"allow": false, "reason": "transfer_funds blocked"} if {
	input.tool == "transfer_funds"
}
`

// regoNeedsArgValue depends on an argument value the dry-run can't
// supply. Used to assert the missing-value warning fires.
const regoNeedsArgValue = `package intentgate.policy
import rego.v1

default decision := {"allow": true, "reason": "default-allow"}

decision := {"allow": false, "reason": "above threshold"} if {
	input.tool == "transfer_funds"
	to_number(input.args.amount_eur) > 10000
}
`

func TestDryRunHappyPath(t *testing.T) {
	t.Parallel()
	events := []audit.Event{
		makeEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot", audit.DecisionAllow, audit.CheckNone, []string{"amount_eur", "recipient"}),
		makeEvent("2026-05-10T10:00:01Z", "read_invoice", "fin-bot", audit.DecisionAllow, audit.CheckNone, []string{"invoice_id"}),
		makeEvent("2026-05-10T10:00:02Z", "transfer_funds", "fin-bot", audit.DecisionBlock, audit.CheckPolicy, []string{"amount_eur"}),
	}

	out, err := DryRun(context.Background(), regoBlockTransfer, events, DryRunOptions{})
	if err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
	if out.Summary.EventsEvaluated != 3 {
		t.Errorf("EventsEvaluated = %d, want 3", out.Summary.EventsEvaluated)
	}
	// candidate distribution: 2 blocks (both transfer_funds), 1 allow (read_invoice)
	if out.Summary.CandidateBlock != 2 || out.Summary.CandidateAllow != 1 {
		t.Errorf("candidate distribution = block:%d allow:%d, want 2/1",
			out.Summary.CandidateBlock, out.Summary.CandidateAllow)
	}
	// Cross-tab: the original-allow transfer becomes a candidate-block (1);
	// the original-block transfer stays block (no change); read_invoice
	// stays allow (no change).
	if out.Summary.AllowToBlock != 1 {
		t.Errorf("AllowToBlock = %d, want 1", out.Summary.AllowToBlock)
	}
	if out.Summary.BlockToAllow != 0 {
		t.Errorf("BlockToAllow = %d, want 0", out.Summary.BlockToAllow)
	}
	// Only the original-allow → candidate-block event should appear as a sample.
	if len(out.Samples) != 1 {
		t.Fatalf("Samples len = %d, want 1", len(out.Samples))
	}
	if out.Samples[0].Tool != "transfer_funds" || out.Samples[0].OriginalDecision != audit.DecisionAllow ||
		out.Samples[0].CandidateOutcome != DryRunBlock {
		t.Errorf("sample[0] = %+v, want tool=transfer_funds orig=allow cand=block", out.Samples[0])
	}
}

func TestDryRunCompileErrorReturned(t *testing.T) {
	t.Parallel()
	_, err := DryRun(context.Background(), "this is not valid rego", nil, DryRunOptions{})
	if err == nil {
		t.Fatal("expected compile error, got nil")
	}
	if !strings.Contains(err.Error(), "compile candidate") {
		t.Errorf("error = %v, want a 'compile candidate' wrap", err)
	}
}

func TestDryRunEmptyRegoRejected(t *testing.T) {
	t.Parallel()
	_, err := DryRun(context.Background(), "", nil, DryRunOptions{})
	if err == nil {
		t.Fatal("expected error for empty source")
	}
}

func TestDryRunWarnsOnMissingArgValues(t *testing.T) {
	t.Parallel()
	// One event whose original decision was allow. The candidate
	// policy references input.args.amount_eur — a value the dry-run
	// can't supply, so OPA evaluates the threshold rule as undefined
	// (NOT an error) and falls through to the default-allow rule.
	// The dry-run should still warn the operator because the static
	// pre-scan saw the value reference in the source.
	events := []audit.Event{
		makeEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot", audit.DecisionAllow, audit.CheckNone, []string{"amount_eur"}),
	}
	out, err := DryRun(context.Background(), regoNeedsArgValue, events, DryRunOptions{})
	if err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
	if len(out.Warnings) == 0 {
		t.Fatal("expected static-pre-scan warning for input.args.<key> reference, got none")
	}
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "argument values") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no warning mentioned 'argument values'; warnings=%v", out.Warnings)
	}
}

func TestDryRunNoArgValueWarningWhenSourceClean(t *testing.T) {
	t.Parallel()
	// regoBlockTransfer keys on tool name only — no input.args.<key>
	// references — so the warning must NOT fire (it would be noise).
	events := []audit.Event{
		makeEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot", audit.DecisionAllow, audit.CheckNone, []string{"amount_eur"}),
	}
	out, err := DryRun(context.Background(), regoBlockTransfer, events, DryRunOptions{})
	if err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
	for _, w := range out.Warnings {
		if strings.Contains(w, "argument values") {
			t.Errorf("unexpected arg-values warning for source without input.args.<key>: %q", w)
		}
	}
}

func TestDryRunWarnsOnEmptyEvents(t *testing.T) {
	t.Parallel()
	out, err := DryRun(context.Background(), regoBlockTransfer, nil, DryRunOptions{})
	if err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
	if len(out.Warnings) == 0 {
		t.Fatal("expected empty-events warning")
	}
}

func TestDryRunSampleCapHonored(t *testing.T) {
	t.Parallel()
	// 250 events that all flip allow→block.
	events := make([]audit.Event, 250)
	for i := range events {
		events[i] = makeEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot",
			audit.DecisionAllow, audit.CheckNone, []string{"amount_eur"})
	}
	out, err := DryRun(context.Background(), regoBlockTransfer, events, DryRunOptions{MaxSamples: 5})
	if err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
	if out.Summary.EventsEvaluated != 250 {
		t.Errorf("EventsEvaluated = %d, want 250", out.Summary.EventsEvaluated)
	}
	if len(out.Samples) != 5 {
		t.Errorf("Samples len = %d, want 5 (cap)", len(out.Samples))
	}
	// All 250 should count in the cross-tab, not just the sampled 5.
	if out.Summary.AllowToBlock != 250 {
		t.Errorf("AllowToBlock = %d, want 250", out.Summary.AllowToBlock)
	}
}

func TestDryRunPreservesArgKeysInSamples(t *testing.T) {
	t.Parallel()
	events := []audit.Event{
		makeEvent("2026-05-10T10:00:00Z", "transfer_funds", "fin-bot",
			audit.DecisionAllow, audit.CheckNone, []string{"amount_eur", "recipient", "memo"}),
	}
	out, err := DryRun(context.Background(), regoBlockTransfer, events, DryRunOptions{})
	if err != nil {
		t.Fatalf("DryRun returned error: %v", err)
	}
	if len(out.Samples) != 1 {
		t.Fatalf("Samples len = %d, want 1", len(out.Samples))
	}
	if got, want := strings.Join(out.Samples[0].ArgKeys, ","), "amount_eur,recipient,memo"; got != want {
		t.Errorf("sample ArgKeys = %q, want %q", got, want)
	}
}

func TestSortSamplesNewestFirst(t *testing.T) {
	t.Parallel()
	samples := []DryRunSample{
		{Timestamp: "2026-05-10T10:00:00Z"},
		{Timestamp: "2026-05-10T12:00:00Z"},
		{Timestamp: "2026-05-10T11:00:00Z"},
	}
	sortSamplesNewestFirst(samples)
	if samples[0].Timestamp != "2026-05-10T12:00:00Z" ||
		samples[1].Timestamp != "2026-05-10T11:00:00Z" ||
		samples[2].Timestamp != "2026-05-10T10:00:00Z" {
		t.Errorf("sort wrong: %+v", samples)
	}
}

// makeEvent builds a minimal audit.Event for tests.
func makeEvent(ts, tool, agent string, dec audit.Decision, check audit.Check, argKeys []string) audit.Event {
	return audit.Event{
		Timestamp:     ts,
		EventName:     "intentgate.tool_call",
		SchemaVersion: "3",
		Decision:      dec,
		Check:         check,
		Tool:          tool,
		AgentID:       agent,
		ArgKeys:       argKeys,
		Tenant:        "default",
	}
}
