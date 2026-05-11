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
