package webhook

import (
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// --- DefaultFilter: which audit events become webhooks ----------

func TestFilterBlockBecomesDeny(t *testing.T) {
	f := DefaultFilter(nil)
	ev := audit.NewEvent(audit.DecisionBlock, "transfer_funds")
	ev.Check = audit.CheckPolicy
	ev.Reason = "above threshold"
	ev.Tenant = "acme"
	ev.AgentID = "finance-bot"

	out, ok := f(ev)
	if !ok {
		t.Fatalf("expected block to project, got skip")
	}
	if out.Event != EventDeny {
		t.Errorf("event=%q want %q", out.Event, EventDeny)
	}
	if out.Severity != SeverityWarning {
		t.Errorf("severity=%q want warning (policy block)", out.Severity)
	}
	if out.Tenant != "acme" || out.AgentID != "finance-bot" || out.Tool != "transfer_funds" {
		t.Errorf("projection lost fields: %+v", out)
	}
}

// Capability + budget + upstream blocks are critical-severity.
func TestFilterCriticalCheckBlocks(t *testing.T) {
	f := DefaultFilter(nil)
	for _, c := range []audit.Check{
		audit.CheckCapability, audit.CheckBudget, audit.CheckUpstream,
	} {
		t.Run(string(c), func(t *testing.T) {
			ev := audit.NewEvent(audit.DecisionBlock, "x")
			ev.Check = c
			out, ok := f(ev)
			if !ok {
				t.Fatalf("expected projection")
			}
			if out.Severity != SeverityCritical {
				t.Errorf("severity=%q want critical for check=%s", out.Severity, c)
			}
		})
	}
}

func TestFilterEscalateBecomesEscalateEvent(t *testing.T) {
	f := DefaultFilter(nil)
	ev := audit.NewEvent(audit.DecisionEscalate, "delete_db")
	ev.PendingID = "pending-123"
	out, ok := f(ev)
	if !ok || out.Event != EventEscalate {
		t.Fatalf("expected escalate event, got ok=%v event=%q", ok, out.Event)
	}
	if out.PendingID != "pending-123" {
		t.Errorf("pending_id lost: %q", out.PendingID)
	}
}

func TestFilterAllowSkippedWhenRoutine(t *testing.T) {
	f := DefaultFilter(nil)
	ev := audit.NewEvent(audit.DecisionAllow, "read_invoice")
	_, ok := f(ev)
	if ok {
		t.Fatalf("expected routine allow to be skipped")
	}
}

// Allow + RequiresStepUp is the soft-observation path: info severity.
func TestFilterAllowWithStepUpEmitsInfo(t *testing.T) {
	f := DefaultFilter(nil)
	ev := audit.NewEvent(audit.DecisionAllow, "transfer_funds")
	ev.RequiresStepUp = true
	out, ok := f(ev)
	if !ok {
		t.Fatalf("expected step-up-required to project even on allow")
	}
	if out.Event != EventStepUpRequired || out.Severity != SeverityInfo {
		t.Errorf("got event=%q severity=%q want %q+%q",
			out.Event, out.Severity, EventStepUpRequired, SeverityInfo)
	}
	if !out.RequiresStepUp {
		t.Errorf("RequiresStepUp flag lost in projection")
	}
}

func TestFilterAdminMintIsSkipped(t *testing.T) {
	f := DefaultFilter(nil)
	ev := audit.NewEvent(audit.DecisionAllow, "admin/mint")
	if _, ok := f(ev); ok {
		t.Errorf("admin/mint should not generate a webhook")
	}
	ev2 := audit.NewEvent(audit.DecisionBlock, "admin/revoke")
	if _, ok := f(ev2); ok {
		t.Errorf("admin/revoke should not generate a webhook")
	}
}

// --- Per-deployment allowlist ----------------------------------

func TestFilterAllowlistNarrows(t *testing.T) {
	// Only deny events allowed; escalates dropped.
	f := DefaultFilter([]string{"intentgate.deny"})

	block := audit.NewEvent(audit.DecisionBlock, "x")
	if _, ok := f(block); !ok {
		t.Errorf("deny should pass the allowlist")
	}

	esc := audit.NewEvent(audit.DecisionEscalate, "x")
	if _, ok := f(esc); ok {
		t.Errorf("escalate should be filtered out by allowlist")
	}
}

func TestFilterEmptyAllowlistAllowsAll(t *testing.T) {
	// Empty / all-whitespace allowlist behaves like nil — accept
	// everything the default filter accepts.
	f := DefaultFilter([]string{"", "   "})
	ev := audit.NewEvent(audit.DecisionBlock, "x")
	if _, ok := f(ev); !ok {
		t.Errorf("empty allowlist should allow default selection")
	}
}
