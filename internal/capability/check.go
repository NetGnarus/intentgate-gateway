package capability

import (
	"errors"
	"fmt"
	"time"
)

// RequestContext is the per-call data the caveat evaluator needs.
//
// AgentID is taken from the verified token's Subject — never from the
// untrusted request body — and is what CaveatAgentLock compares against.
// Tool is the MCP method's tool name. Now is injectable for tests; if
// zero, time.Now() is used.
type RequestContext struct {
	AgentID string
	Tool    string
	Now     time.Time
}

// Check evaluates a token's caveats against ctx in order.
//
// Check returns the first caveat error encountered, or nil if all
// pass. Unknown caveat types are denied: if a token carries a caveat
// this gateway version doesn't understand, it is not safe to allow
// the call — we cannot tell whether the request satisfies a constraint
// we can't even parse.
//
// Check assumes Verify has already succeeded. Callers MUST run Verify
// before Check; otherwise an attacker could craft a token whose
// caveats trivially pass.
func (t *Token) Check(ctx RequestContext) error {
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	if t.NotBefore != 0 && now.Unix() < t.NotBefore {
		return errors.New("token not yet valid (nbf in future)")
	}

	for i, c := range t.Caveats {
		if err := evalCaveat(c, ctx, now); err != nil {
			return fmt.Errorf("caveat %d (%s): %w", i, c.Type, err)
		}
	}
	return nil
}

func evalCaveat(c Caveat, ctx RequestContext, now time.Time) error {
	switch c.Type {
	case CaveatExpiry:
		if c.Expiry == 0 {
			return errors.New("expiry caveat missing exp value")
		}
		if now.Unix() >= c.Expiry {
			return errors.New("expired")
		}
		return nil

	case CaveatAgentLock:
		if c.Agent == "" {
			return errors.New("agent_lock caveat missing agent value")
		}
		if c.Agent != ctx.AgentID {
			return fmt.Errorf("token bound to %q, request from %q", c.Agent, ctx.AgentID)
		}
		return nil

	case CaveatToolWhitelist:
		if !contains(c.Tools, ctx.Tool) {
			return fmt.Errorf("tool %q not in allowed set", ctx.Tool)
		}
		return nil

	case CaveatToolBlacklist:
		if contains(c.Tools, ctx.Tool) {
			return fmt.Errorf("tool %q is forbidden", ctx.Tool)
		}
		return nil

	case CaveatMaxCalls:
		// Informational at this layer. The budget package consults
		// the persistent counter store and enforces the limit as the
		// fourth pipeline check. We accept the caveat as valid here
		// so that signed tokens carrying max_calls aren't rejected
		// by the capability stage.
		return nil

	default:
		return fmt.Errorf("unknown caveat type %q (deny by default)", c.Type)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
