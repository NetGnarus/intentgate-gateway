// Package budget enforces per-token call counters as the fourth check
// in the IntentGate pipeline (capability → intent → policy → budget).
//
// Each capability token may carry one or more max_calls caveats. When
// a request reaches this stage, the gateway looks up the cumulative
// count for the token's id, increments it, and denies the call if any
// caveat's MaxCalls is exceeded.
//
// Two storage backends are provided: [MemoryStore] (process-local,
// fine for single-replica dev and tests) and [RedisStore] (multi-
// replica production). They share the [Store] interface so the handler
// is agnostic to which one it talks to.
//
// Future work: per-minute rate limits, cost-weighted budgets (each tool
// declares an integer cost), and taint propagation for the data-flow
// half of "the fourth check" the deployment diagram describes.
package budget

import (
	"context"
	"fmt"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/capability"
)

// Store is the persistent counter backend.
//
// Increment atomically increments the counter at key by 1 and returns
// the new value. The first call for a key returns 1. ttl bounds how
// long the counter persists; when 0 or negative, the implementation
// chooses a sensible default (24 hours for both backends).
type Store interface {
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// Decision reports whether a request should be permitted by the budget
// stage. Allowed=true means proceed; Allowed=false carries the Reason.
//
// On a deny, Limit is the lowest cap the call would have violated and
// Used is the post-increment count (which equals Limit+1 for the
// caveat that fired).
type Decision struct {
	Allowed bool
	Reason  string
	Limit   int
	Used    int64
}

// Check increments the per-token counter once and verifies the new
// count against every max_calls caveat in the token. The most
// restrictive caveat wins: if any cap is exceeded, the request is
// denied.
//
// Tokens with no max_calls caveats short-circuit to Allowed=true
// without touching the store — a meaningful optimization for the
// common case where budgets are off by default.
func Check(ctx context.Context, store Store, tok *capability.Token) (Decision, error) {
	caps := extractMaxCalls(tok)
	if len(caps) == 0 {
		return Decision{Allowed: true, Reason: "no max_calls caveat"}, nil
	}
	if store == nil {
		return Decision{}, fmt.Errorf("budget: store is nil but token has %d max_calls caveat(s)", len(caps))
	}

	used, err := store.Increment(ctx, "ig:budget:calls:"+tok.ID, 24*time.Hour)
	if err != nil {
		return Decision{}, fmt.Errorf("budget: increment: %w", err)
	}

	// Find the *strictest* limit the request would now violate.
	for _, limit := range caps {
		if used > int64(limit) {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("max_calls exceeded (%d > %d)", used, limit),
				Limit:   limit,
				Used:    used,
			}, nil
		}
	}
	return Decision{Allowed: true, Used: used}, nil
}

// extractMaxCalls returns every positive MaxCalls value in the token's
// caveat chain. Multiple caveats are allowed; the strictest one is what
// matters during evaluation.
func extractMaxCalls(tok *capability.Token) []int {
	out := make([]int, 0, 1)
	for _, c := range tok.Caveats {
		if c.Type == capability.CaveatMaxCalls && c.MaxCalls > 0 {
			out = append(out, c.MaxCalls)
		}
	}
	return out
}
