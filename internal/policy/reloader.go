package policy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Evaluator is the minimal contract every code path that needs to
// run the policy check uses. Both [*Engine] (a single compiled
// snapshot) and [*Reloader] (a live-swappable holder, optionally
// multi-tenant) satisfy it. The MCP handler depends on this
// interface rather than *Engine directly so the deploy-from-console
// workflow can swap the compiled module without restarting the
// gateway, and so per-tenant promotes can dispatch to the right
// engine without changing the handler's call site.
//
// Evaluate's semantics match Engine.Evaluate exactly — when called
// on a Reloader, the input is inspected for [Input.Capability.Tenant]
// to pick the right per-tenant engine, falling back to the default
// fallback engine if the tenant has no promoted policy of its own.
type Evaluator interface {
	Evaluate(ctx context.Context, input any) (Decision, error)
}

// Compile-time interface check.
var (
	_ Evaluator = (*Engine)(nil)
	_ Evaluator = (*Reloader)(nil)
)

// Reloader holds a default fallback engine plus a per-tenant map of
// engines so a request from tenant A and a request from tenant B
// can be evaluated against different compiled Rego modules. The
// MCP request path calls Evaluate; the per-tenant promote/rollback
// admin handlers call SwapFor.
//
// # Dispatch
//
// Evaluate type-asserts the input to [Input] and reads
// `Capability.Tenant`. If the tenant has its own slot in the per-
// tenant map, that engine evaluates. Otherwise the default engine
// evaluates. The default slot is what the v1.4 single-engine
// gateway treated as "the" engine — its initial value comes from
// INTENTGATE_POLICY_FILE / the embedded default at startup, and a
// superadmin promote (tenant="") swaps it.
//
// # Concurrency
//
// The default slot uses an atomic.Pointer for lock-free reads on
// the hot path. The per-tenant map is guarded by an RWMutex; the
// read path takes the RLock for the duration of one map access
// plus the actual Evaluate call, which is fine because the lock
// granularity is per-Reloader, not per-tenant, and the map lookup
// is microseconds while Evaluate is hundreds of microseconds. If
// this ever becomes a bottleneck (it won't at expected scales) the
// per-tenant slots can be promoted to individual atomic.Pointers.
//
// In-flight evaluations against a retired engine remain safe: OPA
// prepared queries are concurrent-safe, and we don't release any
// per-engine resources on swap. The retired engine is GC'd when
// the last in-flight request finishes.
type Reloader struct {
	defaultEngine atomic.Pointer[Engine]

	mu        sync.RWMutex
	perTenant map[string]*Engine
}

// NewReloader wraps an initial default engine. perTenant starts
// empty; SwapFor populates it as tenants promote. The initial
// engine must be non-nil; main.go constructs it via NewEngine just
// like the v1.4 path did.
func NewReloader(initial *Engine) *Reloader {
	r := &Reloader{perTenant: make(map[string]*Engine)}
	r.defaultEngine.Store(initial)
	return r
}

// Current returns the default fallback engine (NOT a per-tenant
// one — there's no single "current" when the gateway is multi-
// tenant). Kept for callers that legitimately want the fallback,
// like tests inspecting the prepared query directly.
func (r *Reloader) Current() *Engine {
	return r.defaultEngine.Load()
}

// CurrentFor returns the engine that would evaluate a request from
// the given tenant. The empty string returns the default engine —
// the same one [Current] does. Useful for tests that want to make
// behavioral assertions per-tenant without going through the
// dispatch + type-assert path of Evaluate.
func (r *Reloader) CurrentFor(tenant string) *Engine {
	if tenant == "" {
		return r.defaultEngine.Load()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if eng, ok := r.perTenant[tenant]; ok {
		return eng
	}
	return r.defaultEngine.Load()
}

// Evaluate dispatches to the right engine for the input's tenant.
//
// Selection rules:
//
//  1. If the input is a [policy.Input] with a non-empty
//     Capability.Tenant AND there's a per-tenant engine for that
//     tenant, that engine evaluates.
//  2. Otherwise the default fallback engine evaluates.
//
// A nil default engine is a programming error (NewReloader
// requires a non-nil initial), but we surface it as an error
// rather than panicking so the gateway's fail-closed deny logic
// kicks in on the caller side.
func (r *Reloader) Evaluate(ctx context.Context, input any) (Decision, error) {
	tenant := extractTenant(input)
	if tenant != "" {
		r.mu.RLock()
		eng, ok := r.perTenant[tenant]
		r.mu.RUnlock()
		if ok && eng != nil {
			return eng.Evaluate(ctx, input)
		}
	}
	def := r.defaultEngine.Load()
	if def == nil {
		return Decision{}, fmt.Errorf("policy: reloader has no engine loaded")
	}
	return def.Evaluate(ctx, input)
}

// extractTenant pulls the tenant string out of a [policy.Input]-
// shaped value. Returns empty for any other shape (tests passing
// raw maps, callers that haven't been updated, etc.) — those
// callers transparently fall back to the default engine.
func extractTenant(input any) string {
	if in, ok := input.(Input); ok && in.Capability != nil {
		return in.Capability.Tenant
	}
	return ""
}

// Swap is the v1.4-compatible single-engine swap; it operates on
// the default fallback slot. Equivalent to SwapFor("", next).
// Kept so the v1.4 promote handler — and the unit tests that use
// Swap directly — keep working without modification.
func (r *Reloader) Swap(next *Engine) (*Engine, error) {
	return r.SwapFor("", next)
}

// SwapFor installs an engine for a specific tenant (or, when
// tenant=="", the default fallback). Returns the prior engine for
// the caller to retire, or nil if no engine was previously
// installed for that tenant. Refuses a nil next.
//
// Visibility: subsequent Evaluate calls observe the new engine
// after this call returns. In-flight calls against the retired
// engine remain correct (OPA prepared queries are concurrent-safe).
func (r *Reloader) SwapFor(tenant string, next *Engine) (*Engine, error) {
	if next == nil {
		return nil, fmt.Errorf("policy: cannot swap to a nil engine")
	}
	if tenant == "" {
		prior := r.defaultEngine.Swap(next)
		return prior, nil
	}
	r.mu.Lock()
	prior := r.perTenant[tenant]
	r.perTenant[tenant] = next
	r.mu.Unlock()
	return prior, nil
}

// RemoveFor drops a tenant's engine slot. Requests from that
// tenant will fall back to the default engine after this returns.
// Idempotent: removing an absent tenant is a no-op.
//
// Used by the rollback path when rollback drains a tenant's
// PreviousDraftID and the operator wants to revert to "no
// per-tenant policy" — though in practice the admin API doesn't
// expose this directly today; it's reserved for future use.
func (r *Reloader) RemoveFor(tenant string) {
	if tenant == "" {
		return
	}
	r.mu.Lock()
	delete(r.perTenant, tenant)
	r.mu.Unlock()
}
