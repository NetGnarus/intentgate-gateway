// Package policy embeds the Open Policy Agent Rego engine inside the
// gateway and runs every tool call through it as the third of the four
// authorization checks (capability → intent → policy → budget).
//
// Why embedded? Two reasons. First, performance: a sidecar OPA would add
// an HTTP round-trip per tool call. Second, ops simplicity: one binary,
// one process, one container. The cost is binary size — OPA pulls in a
// lot of dependencies. For larger deployments where many gateways need
// to share centrally distributed policy bundles, swapping the embedded
// engine for an OPA sidecar is a single-file change behind this
// package's [Engine] interface.
//
// # Policy authoring
//
// Policies are written in Rego, OPA's declarative policy language. The
// gateway expects the policy to define a top-level rule named
// `decision` that returns an object with two or three fields:
//
//	{
//	  "allow":    true | false,
//	  "reason":   "human-readable explanation",
//	  "escalate": true | false  // optional, default false
//	}
//
// When `escalate` is true the gateway treats the call as
// human-approval-required: it pauses the request, enqueues it on the
// approvals queue, and resumes only when an operator approves
// (allowing the call to continue) or rejects (returning a block to
// the agent). `allow` should be set to false when `escalate` is true
// — the gateway treats them as mutually exclusive (escalate wins on
// the rare case both are set).
//
// The package and rule path are fixed at:
//
//	package intentgate.policy
//	decision := {...}
//
// See default_policy.rego for a starter policy that demonstrates a
// realistic mix of allow rules, deny rules, and a numeric threshold.
package policy

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

// QueryPath is the Rego query the engine evaluates for every request.
// Customer-provided policies must populate this rule.
const QueryPath = "data.intentgate.policy.decision"

//go:embed default_policy.rego
var defaultPolicy string

// DefaultPolicy returns the Rego source the gateway uses when no policy
// file is supplied via INTENTGATE_POLICY_FILE.
func DefaultPolicy() string {
	return defaultPolicy
}

// Decision is the verdict returned by the policy engine.
//
// Three legal shapes:
//
//   - Allow=true, Escalate=false  → call proceeds to budget check.
//   - Allow=false, Escalate=false → call blocked at policy stage.
//   - Allow=false, Escalate=true  → call paused for human approval;
//     eventual outcome decided by an
//     operator at /v1/admin/approvals.
type Decision struct {
	Allow    bool
	Escalate bool
	Reason   string
}

// Engine wraps a prepared Rego query. Construct one at startup with
// [NewEngine] and call [Evaluate] for each request — preparation is
// expensive (Rego compilation) and Evaluate is fast.
type Engine struct {
	query rego.PreparedEvalQuery
}

// NewEngine compiles the supplied Rego source and returns an Engine
// ready to evaluate requests.
//
// If source is empty, the embedded default policy is used. The
// returned error wraps any compilation problem reported by OPA.
func NewEngine(ctx context.Context, source string) (*Engine, error) {
	if source == "" {
		source = defaultPolicy
	}
	r := rego.New(
		rego.Query(QueryPath),
		rego.Module("intentgate_policy.rego", source),
	)
	q, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare for eval: %w", err)
	}
	return &Engine{query: q}, nil
}

// Evaluate runs the policy against input and returns the Decision.
//
// Failure modes — any of these return a non-nil error and the caller
// MUST fail closed (treat as deny) when error is non-nil:
//
//   - Rego runtime error.
//   - Query returns no result (no rule matched and there's no default).
//   - Result is not the expected map[string]any shape.
//   - Result missing the "allow" or "reason" fields.
func (e *Engine) Evaluate(ctx context.Context, input any) (Decision, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("policy: eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{}, errors.New("policy: no decision returned (missing default rule?)")
	}
	value := rs[0].Expressions[0].Value
	obj, ok := value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("policy: decision is %T, want map[string]any", value)
	}
	allow, ok := obj["allow"].(bool)
	if !ok {
		return Decision{}, errors.New(`policy: decision missing "allow" boolean`)
	}
	reason, _ := obj["reason"].(string)   // reason is optional; empty is fine
	escalate, _ := obj["escalate"].(bool) // escalate is optional; default false
	return Decision{Allow: allow, Escalate: escalate, Reason: reason}, nil
}

// Input is a convenience builder for the request shape policies see.
//
// The shape mirrors the order of the four-check pipeline: a tool name,
// the args the agent supplied, the agent identifier from the verified
// capability token, and (when present) the structured intent from the
// extractor. Customer policies can ignore fields they don't care about.
type Input struct {
	Tool       string         `json:"tool"`
	Args       map[string]any `json:"args,omitempty"`
	AgentID    string         `json:"agent_id,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	Intent     *InputIntent   `json:"intent,omitempty"`
	Capability *InputCap      `json:"capability,omitempty"`
}

// InputIntent is the intent fields the policy can read.
type InputIntent struct {
	Summary        string   `json:"summary,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	ForbiddenTools []string `json:"forbidden_tools,omitempty"`
	Confidence     float64  `json:"confidence,omitempty"`
}

// InputCap exposes a small slice of the verified capability token.
//
// Tenant is set by the MCP handler from the verified capability
// token (see [capability.Token.Tenant]). The [Reloader] reads it to
// dispatch the evaluation to the right per-tenant compiled engine
// — customer Rego that doesn't care about multi-tenancy can ignore
// the field, and tenants without their own promoted policy fall
// back to the default fallback module installed at startup or by
// a superadmin promote.
type InputCap struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
}
