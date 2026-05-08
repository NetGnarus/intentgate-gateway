package policy

import (
	"context"
	"testing"
)

func newDefault(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(context.Background(), "")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// --- Default policy: allow rules -----------------------------------------

func TestReadStarAllowed(t *testing.T) {
	e := newDefault(t)
	for _, tool := range []string{"read_invoice", "read_ledger", "read_anything_at_all"} {
		t.Run(tool, func(t *testing.T) {
			d, err := e.Evaluate(context.Background(), Input{Tool: tool})
			if err != nil {
				t.Fatal(err)
			}
			if !d.Allow {
				t.Errorf("expected allow for %q, got %+v", tool, d)
			}
		})
	}
}

func TestRoutineWriteAllowed(t *testing.T) {
	e := newDefault(t)
	for _, tool := range []string{"record_in_ledger", "verify_vendor", "fetch_company_data", "web_search"} {
		t.Run(tool, func(t *testing.T) {
			d, err := e.Evaluate(context.Background(), Input{Tool: tool})
			if err != nil {
				t.Fatal(err)
			}
			if !d.Allow {
				t.Errorf("expected allow for %q, got %+v", tool, d)
			}
		})
	}
}

// --- Default policy: deny rules ------------------------------------------

func TestUnknownToolDeniedByDefault(t *testing.T) {
	e := newDefault(t)
	d, err := e.Evaluate(context.Background(), Input{Tool: "send_carrier_pigeon"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Errorf("expected default deny, got allow with reason %q", d.Reason)
	}
}

func TestDestructiveToolsDenied(t *testing.T) {
	e := newDefault(t)
	for _, tool := range []string{"delete", "drop_table", "factory_reset", "purge_audit"} {
		t.Run(tool, func(t *testing.T) {
			d, err := e.Evaluate(context.Background(), Input{Tool: tool})
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow {
				t.Errorf("expected deny for %q, got allow with reason %q", tool, d.Reason)
			}
		})
	}
}

// --- transfer_funds threshold --------------------------------------------

func TestTransferFundsUnderThreshold(t *testing.T) {
	e := newDefault(t)
	d, err := e.Evaluate(context.Background(), Input{
		Tool: "transfer_funds",
		Args: map[string]any{"amount_eur": 1240},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Errorf("expected allow under threshold, got %+v", d)
	}
}

func TestTransferFundsAtThreshold(t *testing.T) {
	// 10_000 EUR exactly should ALLOW (rule is <=, not <).
	e := newDefault(t)
	d, err := e.Evaluate(context.Background(), Input{
		Tool: "transfer_funds",
		Args: map[string]any{"amount_eur": 10000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Errorf("expected allow at threshold, got %+v", d)
	}
}

func TestTransferFundsAboveThreshold(t *testing.T) {
	e := newDefault(t)
	d, err := e.Evaluate(context.Background(), Input{
		Tool: "transfer_funds",
		Args: map[string]any{"amount_eur": 10001},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Errorf("expected deny above threshold, got allow with reason %q", d.Reason)
	}
	if d.Reason == "" {
		t.Errorf("expected reason explaining the deny")
	}
}

// --- Custom policy override ---------------------------------------------

func TestCustomPolicyOverridesDefault(t *testing.T) {
	// Customer policy: allow EVERYTHING. Used to verify NewEngine
	// actually compiles the supplied source instead of always using
	// the embedded default.
	custom := `
package intentgate.policy
import rego.v1
default decision := {"allow": false, "reason": "default"}
decision := {"allow": true, "reason": "custom policy says yes"} if {
	input.tool != ""
}
`
	e, err := NewEngine(context.Background(), custom)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Evaluate(context.Background(), Input{Tool: "delete"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Fatalf("custom policy should allow, got %+v", d)
	}
	if d.Reason != "custom policy says yes" {
		t.Errorf("expected custom reason, got %q", d.Reason)
	}
}

// --- Compilation errors --------------------------------------------------

func TestNewEngineRejectsInvalidRego(t *testing.T) {
	_, err := NewEngine(context.Background(), "this is not rego at all { ]")
	if err == nil {
		t.Fatalf("expected compile error on bogus Rego")
	}
}

// --- Default policy text accessible -------------------------------------

func TestDefaultPolicyExposed(t *testing.T) {
	src := DefaultPolicy()
	if src == "" {
		t.Fatalf("DefaultPolicy() returned empty string")
	}
	// Sanity: the package declaration lives in the embedded source.
	if !contains(src, "package intentgate.policy") {
		t.Errorf("default policy should declare package intentgate.policy")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
