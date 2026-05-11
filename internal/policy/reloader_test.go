package policy

import (
	"context"
	"sync"
	"testing"
)

const reloaderRegoAllow = `package intentgate.policy
import rego.v1
default decision := {"allow": true, "reason": "v1"}
`

const reloaderRegoDeny = `package intentgate.policy
import rego.v1
default decision := {"allow": false, "reason": "v2"}
`

func mustEngine(t *testing.T, src string) *Engine {
	t.Helper()
	e, err := NewEngine(context.Background(), src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return e
}

func TestReloader_EvaluateUsesCurrent(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))

	d, err := r.Evaluate(context.Background(), map[string]any{"tool": "x"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !d.Allow {
		t.Fatal("v1 reloader should allow")
	}
}

func TestReloader_SwapNilRejected(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))
	if _, err := r.Swap(nil); err == nil {
		t.Fatal("Swap(nil) must error to avoid silently breaking the gateway")
	}
	// After a rejected swap, evaluation still works.
	if _, err := r.Evaluate(context.Background(), map[string]any{"tool": "x"}); err != nil {
		t.Fatalf("evaluate after rejected swap: %v", err)
	}
}

func TestReloader_SwapChangesLiveEngine(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))

	pre, _ := r.Evaluate(context.Background(), map[string]any{"tool": "x"})
	if !pre.Allow {
		t.Fatal("expected pre-swap allow")
	}

	prior, err := r.Swap(mustEngine(t, reloaderRegoDeny))
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if prior == nil {
		t.Fatal("Swap should return the prior engine for the caller to retire")
	}

	post, _ := r.Evaluate(context.Background(), map[string]any{"tool": "x"})
	if post.Allow {
		t.Fatal("expected post-swap deny (v2 policy)")
	}
}

// TestReloader_ConcurrentEvaluateAndSwap is the safety contract:
// readers in flight when a swap happens see EITHER the old or the
// new engine, never garbage, never a deadlock. We don't assert which
// — atomic ordering allows either — but every call must succeed.
func TestReloader_ConcurrentEvaluateAndSwap(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))
	const readers = 16
	const iters = 200

	var wg sync.WaitGroup
	wg.Add(readers + 1)

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if _, err := r.Evaluate(context.Background(), map[string]any{"tool": "x"}); err != nil {
					t.Errorf("reader iter %d: %v", j, err)
					return
				}
			}
		}()
	}
	go func() {
		defer wg.Done()
		for j := 0; j < iters; j++ {
			// Alternate engines so the readers see a swap mid-flight.
			src := reloaderRegoAllow
			if j%2 == 0 {
				src = reloaderRegoDeny
			}
			if _, err := r.Swap(mustEngine(t, src)); err != nil {
				t.Errorf("swap iter %d: %v", j, err)
				return
			}
		}
	}()

	wg.Wait()
}

// Compile-time check: both Engine and Reloader satisfy the
// Evaluator interface. Catches a regression on the type swap if
// either implementation drifts.
func TestEvaluatorInterfaceSatisfied(t *testing.T) {
	t.Parallel()
	var _ Evaluator = (*Engine)(nil)
	var _ Evaluator = (*Reloader)(nil)
}

// --- Per-tenant dispatch tests (session 38) ---

const reloaderRegoAcmeOnly = `package intentgate.policy
import rego.v1
default decision := {"allow": false, "reason": "acme-only deny-default"}
decision := {"allow": true, "reason": "acme allowed"} if {
    input.capability.tenant == "acme"
}
`

// TestReloader_DispatchesByTenant: per-tenant engines installed
// via SwapFor are picked up by Evaluate based on the input's
// Capability.Tenant. A request with a different tenant falls back
// to the default engine.
func TestReloader_DispatchesByTenant(t *testing.T) {
	t.Parallel()
	// Default engine allows everything (v1).
	r := NewReloader(mustEngine(t, reloaderRegoAllow))
	// Acme-specific engine: v2 (deny-all).
	acmeEngine := mustEngine(t, reloaderRegoDeny)
	if _, err := r.SwapFor("acme", acmeEngine); err != nil {
		t.Fatalf("SwapFor acme: %v", err)
	}

	// Request from acme → evaluates against the acme engine (deny).
	acmeIn := Input{Tool: "x", Capability: &InputCap{Tenant: "acme"}}
	acmeDec, err := r.Evaluate(context.Background(), acmeIn)
	if err != nil {
		t.Fatalf("evaluate acme: %v", err)
	}
	if acmeDec.Allow {
		t.Errorf("acme request should evaluate against acme engine (deny), got allow")
	}

	// Request from globex (no slot) → falls back to default (allow).
	globexIn := Input{Tool: "x", Capability: &InputCap{Tenant: "globex"}}
	globexDec, err := r.Evaluate(context.Background(), globexIn)
	if err != nil {
		t.Fatalf("evaluate globex: %v", err)
	}
	if !globexDec.Allow {
		t.Errorf("globex request should fall back to default engine (allow), got deny")
	}

	// Request with no tenant → also falls back to default.
	noTenantIn := Input{Tool: "x", Capability: &InputCap{}}
	defDec, err := r.Evaluate(context.Background(), noTenantIn)
	if err != nil {
		t.Fatalf("evaluate no-tenant: %v", err)
	}
	if !defDec.Allow {
		t.Errorf("no-tenant request should evaluate default engine (allow)")
	}
}

// TestReloader_RemoveForFallsBackToDefault: after RemoveFor, a
// tenant's requests evaluate against the default engine.
func TestReloader_RemoveForFallsBackToDefault(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))
	if _, err := r.SwapFor("acme", mustEngine(t, reloaderRegoDeny)); err != nil {
		t.Fatalf("SwapFor: %v", err)
	}

	in := Input{Tool: "x", Capability: &InputCap{Tenant: "acme"}}
	dec, _ := r.Evaluate(context.Background(), in)
	if dec.Allow {
		t.Fatal("expected acme deny before RemoveFor")
	}

	r.RemoveFor("acme")
	dec, _ = r.Evaluate(context.Background(), in)
	if !dec.Allow {
		t.Fatal("expected fallback-to-default allow after RemoveFor")
	}
}

// TestReloader_PerTenantSwapDoesNotTouchDefault: installing a
// tenant engine must not affect the default slot.
func TestReloader_PerTenantSwapDoesNotTouchDefault(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))
	defaultBefore := r.Current()

	if _, err := r.SwapFor("acme", mustEngine(t, reloaderRegoDeny)); err != nil {
		t.Fatalf("SwapFor: %v", err)
	}

	if r.Current() != defaultBefore {
		t.Fatal("per-tenant SwapFor changed the default-engine pointer")
	}
}

// TestReloader_SwapForEmptyTenantUpdatesDefault: the empty tenant
// is an alias for the default slot — needed for the v1.4-
// compatible Swap() path that the superadmin promote handler uses.
func TestReloader_SwapForEmptyTenantUpdatesDefault(t *testing.T) {
	t.Parallel()
	r := NewReloader(mustEngine(t, reloaderRegoAllow))
	newDefault := mustEngine(t, reloaderRegoDeny)
	if _, err := r.SwapFor("", newDefault); err != nil {
		t.Fatalf("SwapFor empty: %v", err)
	}
	if r.Current() != newDefault {
		t.Fatal("SwapFor('') should update the default-engine pointer")
	}
}
