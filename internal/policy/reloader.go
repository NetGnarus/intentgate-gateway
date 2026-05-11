package policy

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Evaluator is the minimal contract every code path that needs to
// run the policy check uses. Both [*Engine] (a compiled snapshot)
// and [*Reloader] (a live-swappable holder) satisfy it. The MCP
// handler depends on this interface rather than *Engine directly so
// session 35's "deploy from console" workflow can swap the compiled
// module without restarting the gateway.
//
// Evaluate's semantics match Engine.Evaluate exactly — Reloader's
// implementation is a thin wrapper that forwards to whatever Engine
// is current at call time.
type Evaluator interface {
	Evaluate(ctx context.Context, input any) (Decision, error)
}

// Compile-time interface check: both types implement Evaluator.
var (
	_ Evaluator = (*Engine)(nil)
	_ Evaluator = (*Reloader)(nil)
)

// Reloader holds an [*Engine] behind an atomic pointer so the
// gateway's request path can read the current engine on every call
// while an admin handler swaps it for a freshly-compiled module
// after a promote or rollback.
//
// The atomic pointer is the right primitive here. Evaluate calls
// happen on the hot path and must not contend with each other or
// with the (rare) Swap. A RWMutex would serialize Evaluate calls
// against Swap; atomic.Pointer makes Evaluate lock-free and Swap
// O(1).
//
// Note that Evaluate operates on a Rego prepared query inside the
// pointed-to Engine. The prepared query is itself safe for
// concurrent evaluation per OPA's docs, so a Swap that retires an
// old Engine while in-flight evaluations are still using it is
// fine: the in-flight call finishes against the old module, every
// new call after the atomic store sees the new module. No
// quiescence required.
type Reloader struct {
	current atomic.Pointer[Engine]
}

// NewReloader wraps an initial Engine. The Engine must be non-nil;
// callers (main.go) construct it via NewEngine just like before.
func NewReloader(initial *Engine) *Reloader {
	r := &Reloader{}
	r.current.Store(initial)
	return r
}

// Current returns the currently-loaded Engine. Useful when a caller
// wants the *Engine concrete type — e.g. tests, or future code that
// needs to inspect the prepared query directly. Returns nil only if
// Swap has been called with nil, which is a misuse.
func (r *Reloader) Current() *Engine {
	return r.current.Load()
}

// Evaluate forwards to the current Engine. If the current pointer
// is nil (shouldn't happen given a correctly-constructed Reloader),
// it returns an error rather than panicking so the gateway's
// fail-closed deny logic kicks in on the caller side.
func (r *Reloader) Evaluate(ctx context.Context, input any) (Decision, error) {
	eng := r.current.Load()
	if eng == nil {
		return Decision{}, fmt.Errorf("policy: reloader has no engine loaded")
	}
	return eng.Evaluate(ctx, input)
}

// Swap installs a freshly-compiled engine and returns the prior
// one. The caller can discard the prior engine immediately —
// in-flight evaluations against it remain safe (Rego prepared
// queries are concurrent-safe, and we don't release any resources
// associated with the engine on retirement).
//
// Returns an error only when next is nil — refusing rather than
// silently breaking the gateway is the right ergonomic.
func (r *Reloader) Swap(next *Engine) (*Engine, error) {
	if next == nil {
		return nil, fmt.Errorf("policy: cannot swap to a nil engine")
	}
	prior := r.current.Swap(next)
	return prior, nil
}
