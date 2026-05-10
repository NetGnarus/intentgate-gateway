package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/approvals"
	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/budget"
	"github.com/NetGnarus/intentgate-gateway/internal/capability"
	"github.com/NetGnarus/intentgate-gateway/internal/extractor"
	"github.com/NetGnarus/intentgate-gateway/internal/mcp"
	"github.com/NetGnarus/intentgate-gateway/internal/metrics"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
	"github.com/NetGnarus/intentgate-gateway/internal/upstream"
)

// MCPHandlerConfig configures the /v1/mcp handler.
type MCPHandlerConfig struct {
	// Logger is required.
	Logger *slog.Logger
	// MasterKey is the HMAC key for capability tokens. May be nil only
	// when RequireCapability is false (dev mode).
	MasterKey []byte
	// RequireCapability rejects requests that don't carry a valid
	// capability token. When false (default in dev), missing tokens are
	// allowed through with a warning logged.
	RequireCapability bool
	// Extractor is the optional intent-extractor client. When nil, the
	// intent check is skipped. When non-nil, every tools/call carrying
	// an X-Intent-Prompt header is checked against the extracted intent.
	Extractor *extractor.Client
	// RequireIntent rejects requests that don't carry an
	// X-Intent-Prompt header. Independent of RequireCapability.
	RequireIntent bool
	// Policy is the OPA-backed policy engine, evaluated as the third of
	// the four checks. May be nil only in dev mode (the policy check is
	// skipped). main.go always supplies one in normal operation.
	Policy *policy.Engine
	// Budget is the per-token call counter store. When nil, the budget
	// check is skipped (and tokens with max_calls caveats produce a
	// startup-time error rather than a runtime one). When RequireBudget
	// is true, missing tokens at this stage are rejected.
	Budget budget.Store
	// RequireBudget rejects /v1/mcp tools/call requests that don't
	// have a verified capability token reaching the budget stage.
	// Default false (dev mode allows missing tokens).
	RequireBudget bool
	// Audit is the emitter for one-event-per-decision audit records.
	// When nil, a NullEmitter is substituted so the handler always has
	// a safe target.
	Audit audit.Emitter
	// Upstream forwards authorized tools/call requests to a downstream
	// MCP tool server. When nil, the handler returns a stub allow result
	// (useful for SDK tests, smoke targets, and any deployment that
	// hasn't wired a real upstream yet).
	Upstream *upstream.Client
	// Revocation is the store the capability check consults to reject
	// tokens revoked after issuance. When nil, the revocation step is
	// skipped (useful for tests and minimal dev installs). Production
	// deployments always supply one (memory-backed for single-replica
	// dev, Postgres-backed for multi-replica or auditable installs).
	Revocation revocation.Store
	// Metrics is the Prometheus instrumentation. nil disables all
	// observation calls (the helpers nil-check internally so handlers
	// don't need to).
	Metrics *metrics.Metrics
	// Approvals is the queue the handler uses when policy returns
	// escalate. nil disables the escalation path: a policy
	// returning escalate without an approvals store wired
	// degrades to block ("escalate not configured").
	Approvals approvals.Store
	// ApprovalTimeout caps how long the handler waits for a human
	// decision before timing out and returning block. Zero falls
	// back to 5 minutes — operators with on-call humans can lower
	// this; deployments with offline reviewers should raise it.
	ApprovalTimeout time.Duration
}

type mcpHandler struct {
	cfg MCPHandlerConfig
}

// NewMCPHandler returns the HTTP handler for POST /v1/mcp.
//
// Pipeline (v0.1):
//
//  1. Parse the JSON-RPC envelope.
//  2. Dispatch on method. Only "tools/call" is implemented.
//  3. Capability check: verify the Bearer token's HMAC chain and
//     evaluate its caveats against the requested tool. Returns
//     CodeCapabilityFailed (-32010) on failure.
//  4. Intent check: if an X-Intent-Prompt header is present and an
//     extractor is configured, the gateway extracts structured intent
//     (cached) and verifies the requested tool is permitted by it.
//     Returns CodeIntentFailed (-32011) on failure.
//  5. Policy check: evaluate the request against the configured Rego
//     policy bundle. Returns CodePolicyFailed (-32012) on deny.
//  6. Budget check: increment the per-token counter, deny when any
//     max_calls caveat in the verified token is exceeded. Returns
//     CodeBudgetFailed (-32013) on deny.
//  7. Return the stub allow response.
func NewMCPHandler(cfg MCPHandlerConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return &mcpHandler{cfg: cfg}
}

func (h *mcpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	const maxBody = 1 << 20
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		h.write(w, mcp.NewErrorResponse(nil, mcp.CodeParseError,
			"failed to read request body", err.Error()))
		return
	}

	var req mcp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		h.write(w, mcp.NewErrorResponse(nil, mcp.CodeParseError,
			"invalid JSON", err.Error()))
		return
	}
	if err := req.Validate(); err != nil {
		h.write(w, mcp.NewErrorResponse(req.ID, mcp.CodeInvalidRequest,
			err.Error(), nil))
		return
	}

	notification := req.IsNotification()

	switch req.Method {
	case mcp.MethodToolsCall:
		resp := h.handleToolsCall(r.Context(), &req, r)
		if notification {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, resp)

	case mcp.MethodToolsList, mcp.MethodInitialize, mcp.MethodPing:
		// Discovery + lifecycle methods: pure passthrough to the upstream
		// when configured, minimal local fallback otherwise. No
		// four-check pipeline (no tool name to authorize) and no audit
		// event (audit is for authorization decisions, not handshake).
		resp := h.handlePassthrough(r.Context(), &req, body)
		if notification {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, resp)

	default:
		h.cfg.Logger.Info("mcp method not implemented",
			"method", req.Method,
			"notification", notification,
		)
		if notification {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, mcp.NewErrorResponse(req.ID, mcp.CodeMethodNotFound,
			"method not implemented in v0.1: "+req.Method, nil))
	}
}

// handleToolsCall runs each enabled check in order then returns the
// stub allow result. Every decision (allow or block at any stage)
// emits one audit event before the response is returned.
func (h *mcpHandler) handleToolsCall(ctx context.Context, req *mcp.Request, r *http.Request) *mcp.Response {
	start := time.Now()

	params, err := mcp.ParseToolCallParams(req.Params)
	if err != nil {
		return mcp.NewErrorResponse(req.ID, mcp.CodeInvalidParams,
			"invalid tools/call params", err.Error())
	}
	if params.Name == "" {
		return mcp.NewErrorResponse(req.ID, mcp.CodeInvalidParams,
			"params.name is required", nil)
	}

	var (
		capResult capabilityCheckResult
		intResult intentCheckResult
	)

	// Check 1: capability.
	capStart := time.Now()
	capResult = h.runCapabilityCheck(r, params.Name)
	h.cfg.Metrics.ObserveCheck("capability", checkDecision(capResult.err, capResult.summary), time.Since(capStart))
	if capResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "capability",
			"reason", capResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckCapability, capResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeCapabilityFailed,
			"capability check failed", capResult.err.Error())
	}

	// Check 2: intent.
	intStart := time.Now()
	intResult = h.runIntentCheck(ctx, r, params.Name, capResult.agentID)
	h.cfg.Metrics.ObserveCheck("intent", checkDecision(intResult.err, intResult.summary), time.Since(intStart))
	if intResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "intent",
			"agent", capResult.agentID, "reason", intResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckIntent, intResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeIntentFailed,
			"intent check failed", intResult.err.Error())
	}

	// Check 3: policy (OPA / Rego).
	polStart := time.Now()
	polResult := h.runPolicyCheck(ctx, params, capResult, intResult)
	h.cfg.Metrics.ObserveCheck("policy", checkDecision(polResult.err, polResult.summary), time.Since(polStart))
	if polResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "policy",
			"agent", capResult.agentID, "reason", polResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckPolicy, polResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy check failed", polResult.err.Error())
	}

	// Check 3b: human approval. Triggered when the Rego policy
	// returns {"escalate": true}. The handler pauses the request
	// here and resumes when an operator decides via
	// /v1/admin/approvals/{id}/decide. Failure modes (queue not
	// wired, queue error, timeout, rejection) all collapse to a
	// CodePolicyFailed block — the agent doesn't need to know the
	// flow took a detour through human review.
	if polResult.escalate {
		if escResp := h.runApprovalFlow(ctx, r, req, params, capResult, intResult, polResult.reason, start); escResp != nil {
			return escResp
		}
	}

	// Check 4: budget.
	bdgStart := time.Now()
	bdgResult := h.runBudgetCheck(ctx, capResult)
	h.cfg.Metrics.ObserveCheck("budget", checkDecision(bdgResult.err, bdgResult.summary), time.Since(bdgStart))
	if bdgResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name, "check", "budget",
			"agent", capResult.agentID, "reason", bdgResult.err.Error())
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckBudget, bdgResult.err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeBudgetFailed,
			"budget check failed", bdgResult.err.Error())
	}

	// Argument values may contain sensitive data — log only the keys.
	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}
	h.cfg.Logger.Info("mcp tools/call authorized",
		"tool", params.Name,
		"agent", capResult.agentID,
		"capability", capResult.summary,
		"intent", intResult.summary,
		"policy", polResult.summary,
		"budget", bdgResult.summary,
		"arg_keys", argKeys,
	)

	// All four checks passed. Either forward to the configured upstream
	// or return the stub allow.
	if h.cfg.Upstream != nil {
		return h.forwardToUpstream(ctx, r, req, params, capResult, intResult, start)
	}

	h.emitAudit(ctx, r, params, capResult, intResult,
		audit.DecisionAllow, audit.CheckNone, "all four checks passed (stub upstream)", start, 0)

	result := mcp.ToolCallResult{
		Content: []mcp.ContentBlock{{
			Type: "text",
			Text: "stub: no upstream configured; gateway authorized this call",
		}},
		IsError: false,
		IntentGate: &mcp.IntentGateMetadata{
			Decision:  "allow",
			Reason:    "stub: no upstream configured",
			LatencyMS: time.Since(start).Milliseconds(),
		},
	}
	resp, err := mcp.NewResultResponse(req.ID, result)
	if err != nil {
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"failed to encode result", err.Error())
	}
	return resp
}

// forwardToUpstream re-serializes the validated request, sends it to
// the configured upstream MCP server, and translates the upstream
// response (or failure) back to the caller.
//
// Successful forwards inject the gateway's _intentgate metadata into
// the upstream's result object. Operational failures (timeout,
// transport, non-2xx) collapse into a JSON-RPC error with the
// gateway's CodeInternalError plus a structured data field, AND emit
// an audit event with check=upstream so SOC analysts can distinguish
// "blocked by gateway" from "couldn't reach upstream".
//
// Upstream-side JSON-RPC errors (a 200 OK carrying an error object —
// e.g. tool says "db unavailable") are NOT operational failures here:
// the upstream answered, the answer just says no. The body is
// returned to the caller unchanged.
func (h *mcpHandler) forwardToUpstream(
	ctx context.Context,
	r *http.Request,
	req *mcp.Request,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
	start time.Time,
) *mcp.Response {
	// Re-serialize the validated request so we forward exactly the
	// envelope the gateway accepted (preserves id and params).
	body, err := json.Marshal(req)
	if err != nil {
		h.emitAudit(ctx, r, params, cap, intent,
			audit.DecisionBlock, audit.CheckUpstream,
			"failed to re-serialize request: "+err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"failed to encode upstream request", err.Error())
	}

	upStart := time.Now()
	upResp, err := h.cfg.Upstream.Forward(ctx, body)
	upDur := time.Since(upStart)
	if err != nil {
		var uerr *upstream.Error
		if errors.As(err, &uerr) {
			reason := uerr.Error()
			h.cfg.Logger.Warn("upstream forward failed",
				"tool", params.Name,
				"agent", cap.agentID,
				"kind", uerr.Kind.String(),
				"status", uerr.Status,
				"reason", reason,
			)
			h.cfg.Metrics.ObserveUpstream(uerr.Kind.String(), upDur)
			h.cfg.Metrics.ObserveCheck("upstream", "block", upDur)
			h.emitAudit(ctx, r, params, cap, intent,
				audit.DecisionBlock, audit.CheckUpstream, reason, start, uerr.Status)
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"upstream "+uerr.Kind.String(),
				map[string]any{
					"upstream_status": uerr.Status,
					"detail":          reason,
				})
		}
		// Defensive: any non-typed error from Forward is treated as transport.
		h.cfg.Metrics.ObserveUpstream("transport", upDur)
		h.cfg.Metrics.ObserveCheck("upstream", "block", upDur)
		h.emitAudit(ctx, r, params, cap, intent,
			audit.DecisionBlock, audit.CheckUpstream, err.Error(), start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"upstream error", err.Error())
	}
	h.cfg.Metrics.ObserveUpstream("success", upDur)
	h.cfg.Metrics.ObserveCheck("upstream", "allow", upDur)

	// Successful forward. Inject _intentgate metadata into the result
	// object so the caller can see the gateway's decision summary
	// alongside the tool's response.
	var parsed mcp.Response
	if err := json.Unmarshal(upResp.Body, &parsed); err != nil {
		h.cfg.Logger.Error("upstream returned non-JSON-RPC body",
			"tool", params.Name,
			"err", err,
		)
		h.emitAudit(ctx, r, params, cap, intent,
			audit.DecisionBlock, audit.CheckUpstream,
			"upstream returned non-JSON-RPC body: "+err.Error(), start, upResp.Status)
		return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
			"upstream returned non-JSON-RPC body", err.Error())
	}

	if parsed.Result != nil {
		parsed.Result = injectIntentGateMetadata(parsed.Result, mcp.IntentGateMetadata{
			Decision:  "allow",
			Reason:    "forwarded",
			LatencyMS: time.Since(start).Milliseconds(),
		})
	}

	h.emitAudit(ctx, r, params, cap, intent,
		audit.DecisionAllow, audit.CheckUpstream, "forwarded", start, upResp.Status)

	return &parsed
}

// handlePassthrough handles MCP discovery and lifecycle methods —
// tools/list, initialize, ping — that don't fit the four-check
// authorization pipeline (no tool name to evaluate). When an upstream
// is configured, the request is forwarded verbatim and the upstream's
// response is returned unchanged. When no upstream is configured, a
// minimal local response keeps an MCP handshake working against a
// standalone gateway:
//
//   - initialize  → advertises protocolVersion + serverInfo
//   - tools/list  → empty list (no upstream means no real tools)
//   - ping        → empty success
//
// No _intentgate metadata is injected (these aren't authorization
// decisions) and no audit event is emitted (audit is reserved for
// tools/call decisions; flooding it with handshake noise would dilute
// signal-to-noise for SOC analysts).
func (h *mcpHandler) handlePassthrough(ctx context.Context, req *mcp.Request, body []byte) *mcp.Response {
	if h.cfg.Upstream != nil {
		upResp, err := h.cfg.Upstream.Forward(ctx, body)
		if err != nil {
			var uerr *upstream.Error
			if errors.As(err, &uerr) {
				h.cfg.Logger.Warn("upstream passthrough failed",
					"method", req.Method,
					"kind", uerr.Kind.String(),
					"status", uerr.Status,
					"err", uerr.Error(),
				)
				return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
					"upstream "+uerr.Kind.String(),
					map[string]any{
						"upstream_status": uerr.Status,
						"detail":          uerr.Error(),
					})
			}
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"upstream error", err.Error())
		}

		var parsed mcp.Response
		if err := json.Unmarshal(upResp.Body, &parsed); err != nil {
			h.cfg.Logger.Error("upstream returned non-JSON-RPC body",
				"method", req.Method, "err", err)
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"upstream returned non-JSON-RPC body", err.Error())
		}
		return &parsed
	}

	// No upstream configured — return a minimal local response so an
	// MCP handshake against a stub-mode gateway still completes cleanly.
	switch req.Method {
	case mcp.MethodInitialize:
		resp, err := mcp.NewResultResponse(req.ID, mcp.InitializeResult{
			ProtocolVersion: "2025-03-26",
			ServerInfo: mcp.ServerInfo{
				Name:    "intentgate",
				Version: "0.2",
			},
			Capabilities: map[string]any{
				"tools": map[string]any{},
			},
		})
		if err != nil {
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"failed to encode initialize result", err.Error())
		}
		return resp

	case mcp.MethodToolsList:
		resp, err := mcp.NewResultResponse(req.ID, map[string]any{
			"tools": []any{},
		})
		if err != nil {
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"failed to encode tools/list result", err.Error())
		}
		return resp

	case mcp.MethodPing:
		resp, err := mcp.NewResultResponse(req.ID, map[string]any{})
		if err != nil {
			return mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"failed to encode ping result", err.Error())
		}
		return resp
	}

	// Unreachable: ServeHTTP only dispatches the three methods above to
	// this handler. Defensive fallback in case the dispatch is widened.
	return mcp.NewErrorResponse(req.ID, mcp.CodeMethodNotFound,
		"method not implemented in passthrough: "+req.Method, nil)
}

// injectIntentGateMetadata adds (or replaces) the "_intentgate"
// vendor-extension field on the upstream's result object. If the
// result isn't a JSON object (unusual but legal), the original bytes
// are returned unchanged.
func injectIntentGateMetadata(result json.RawMessage, meta mcp.IntentGateMetadata) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		return result
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return result
	}
	obj["_intentgate"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return result
	}
	return out
}

// capabilityCheckResult bundles what the capability stage learned.
type capabilityCheckResult struct {
	agentID string
	summary string
	// token is the verified token, retained so subsequent stages
	// (intent, policy, budget) can read its caveats. nil when no token
	// was supplied.
	token *capability.Token
	err   error
}

// intentCheckResult bundles what the intent stage learned.
type intentCheckResult struct {
	summary string                     // short description for logs
	intent  *extractor.ExtractedIntent // populated when extraction ran; nil if skipped
	err     error
}

// defaultApprovalTimeout is used when the operator did not set
// MCPHandlerConfig.ApprovalTimeout. Five minutes is a deliberate
// midpoint between "synchronous reviewers can keep up" and "agent
// HTTP clients won't drop the connection."
const defaultApprovalTimeout = 5 * time.Minute

// runApprovalFlow handles the escalate path. Returns a non-nil
// JSON-RPC response when the call should NOT proceed (queue
// misconfigured, enqueue error, rejected, timed out). Returns nil
// when the operator approved and the caller should resume the
// pipeline (continue to the budget check).
func (h *mcpHandler) runApprovalFlow(
	ctx context.Context,
	r *http.Request,
	req *mcp.Request,
	params *mcp.ToolCallParams,
	capResult capabilityCheckResult,
	intResult intentCheckResult,
	policyReason string,
	start time.Time,
) *mcp.Response {
	// No queue wired? Block. We refuse to silently allow a call the
	// policy specifically said needed human review.
	if h.cfg.Approvals == nil {
		reason := "escalation required but no approvals queue configured (set INTENTGATE_APPROVAL_QUEUE)"
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckPolicy, reason, start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation required", reason)
	}

	pending := approvals.PendingRequest{
		AgentID:       capResult.agentID,
		Tool:          params.Name,
		Args:          params.Arguments,
		IntentSummary: intentSummary(intResult),
		Reason:        policyReason,
	}
	if capResult.token != nil {
		pending.CapabilityTokenID = capResult.token.ID
		pending.RootCapabilityTokenID = capResult.token.RootID
	}

	row, err := h.cfg.Approvals.Enqueue(ctx, pending)
	if err != nil {
		reason := "approval queue: " + err.Error()
		h.cfg.Logger.Error("approval enqueue failed", "err", err, "tool", params.Name)
		h.emitAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, audit.CheckPolicy, reason, start, 0)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation failed", reason)
	}

	// Audit the escalation. PendingID lets SOC join this event with
	// the eventual approve / reject / timeout event.
	h.emitApprovalAudit(ctx, r, params, capResult, intResult,
		audit.DecisionEscalate, "escalate: "+policyReason, row.PendingID, "", start)

	timeout := h.cfg.ApprovalTimeout
	if timeout <= 0 {
		timeout = defaultApprovalTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	final, werr := h.cfg.Approvals.Wait(waitCtx, row.PendingID)
	if werr != nil {
		reason := "approval wait: " + werr.Error()
		h.cfg.Logger.Error("approval wait failed", "err", werr, "pending_id", row.PendingID)
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, reason, row.PendingID, "", start)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation failed", reason)
	}

	switch final.Status {
	case approvals.StatusApproved:
		// Audit the human approval as a CheckPolicy allow so the
		// SOC log shows the human-in-the-loop step. The pipeline
		// continues to budget and then upstream; that final
		// allow/forward emits its own audit too.
		reason := "approved by " + safeDecidedBy(final)
		if final.DecideNote != "" {
			reason += ": " + final.DecideNote
		}
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionAllow, reason, row.PendingID, final.DecidedBy, start)
		h.cfg.Logger.Info("mcp tools/call approved by human",
			"tool", params.Name, "agent", capResult.agentID,
			"pending_id", row.PendingID, "by", final.DecidedBy)
		return nil

	case approvals.StatusRejected:
		reason := "rejected by " + safeDecidedBy(final)
		if final.DecideNote != "" {
			reason += ": " + final.DecideNote
		}
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, reason, row.PendingID, final.DecidedBy, start)
		h.cfg.Logger.Info("mcp tools/call rejected by human",
			"tool", params.Name, "agent", capResult.agentID,
			"pending_id", row.PendingID, "by", final.DecidedBy)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy: rejected by reviewer", reason)

	case approvals.StatusTimeout:
		reason := "approval window expired (" + timeout.String() + ")"
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, reason, row.PendingID, "", start)
		h.cfg.Logger.Info("mcp tools/call approval timed out",
			"tool", params.Name, "agent", capResult.agentID,
			"pending_id", row.PendingID)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy: approval window expired", reason)

	default:
		reason := "unexpected approval status: " + string(final.Status)
		h.emitApprovalAudit(ctx, r, params, capResult, intResult,
			audit.DecisionBlock, reason, row.PendingID, "", start)
		return mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
			"policy escalation failed", reason)
	}
}

// emitApprovalAudit is emitAudit with two extra fields populated
// (pending_id, decided_by). Lets the SOC analyst reconstruct an
// approval lifecycle by filtering on pending_id.
func (h *mcpHandler) emitApprovalAudit(
	ctx context.Context,
	r *http.Request,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
	decision audit.Decision,
	reason string,
	pendingID string,
	decidedBy string,
	start time.Time,
) {
	if h.cfg.Audit == nil {
		return
	}

	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}

	e := audit.NewEvent(decision, params.Name)
	e.Check = audit.CheckPolicy
	e.Reason = reason
	e.AgentID = cap.agentID
	e.ArgKeys = argKeys
	e.LatencyMS = time.Since(start).Milliseconds()
	e.RemoteIP = r.RemoteAddr
	e.PendingID = pendingID
	e.DecidedBy = decidedBy

	if cap.token != nil {
		e.CapabilityTokenID = cap.token.ID
		e.RootCapabilityTokenID = cap.token.RootID
		e.CaveatCount = cap.token.CaveatCount()
	}
	if intent.intent != nil {
		e.IntentSummary = intent.intent.Summary
	}

	h.cfg.Audit.Emit(ctx, e)
}

// intentSummary returns the captured intent summary (or empty).
// Helper for runApprovalFlow's PendingRequest building.
func intentSummary(r intentCheckResult) string {
	if r.intent == nil {
		return ""
	}
	return r.intent.Summary
}

// safeDecidedBy returns the operator identity, or "(anonymous)" when
// blank — useful so the audit reason field is never an awkward
// "approved by ".
func safeDecidedBy(p approvals.PendingRequest) string {
	if p.DecidedBy == "" {
		return "(anonymous)"
	}
	return p.DecidedBy
}

// policyCheckResult bundles what the policy stage learned.
type policyCheckResult struct {
	summary  string // short description ("ok: <reason>", "skipped (no engine)", ...)
	err      error
	escalate bool   // policy returned {"escalate": true} — pause for human review
	reason   string // operator-readable reason (used as summary on escalate path)
}

// budgetCheckResult bundles what the budget stage learned.
type budgetCheckResult struct {
	summary string // short description ("ok: 3/10 calls", "skipped", ...)
	err     error
}

// runCapabilityCheck verifies the Bearer token's HMAC chain, consults
// the revocation store, and evaluates the token's caveats against the
// requested tool. Returns the first failure; on success, the verified
// token (with subject filled in) is included in the result for later
// stages.
//
// Revocation is checked after signature verification but before caveat
// evaluation: if a genuine-but-revoked token is presented, the
// resulting error says "token revoked" rather than "tool not allowed",
// which is the more accurate audit story.
//
// A non-nil error from the revocation store fails closed (treats the
// token as revoked). A partial outage of the revocation store must
// not become a quiet authorization bypass.
func (h *mcpHandler) runCapabilityCheck(r *http.Request, tool string) capabilityCheckResult {
	encoded, err := capability.FromAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return capabilityCheckResult{err: err}
	}
	if encoded == "" {
		if h.cfg.RequireCapability {
			return capabilityCheckResult{err: errMissingCapability}
		}
		h.cfg.Logger.Warn("capability check skipped (no token)",
			"tool", tool,
			"hint", "set INTENTGATE_REQUIRE_CAPABILITY=true to enforce")
		return capabilityCheckResult{summary: "skipped (no token)"}
	}

	tok, err := capability.Decode(encoded)
	if err != nil {
		return capabilityCheckResult{err: err}
	}
	if err := tok.Verify(h.cfg.MasterKey); err != nil {
		return capabilityCheckResult{err: err}
	}

	if h.cfg.Revocation != nil {
		revStart := time.Now()
		revoked, rerr := h.cfg.Revocation.IsRevoked(r.Context(), tok.ID)
		revDur := time.Since(revStart)
		switch {
		case rerr != nil:
			h.cfg.Metrics.ObserveRevocation("error", revDur)
			h.cfg.Logger.Error("revocation lookup failed; failing closed",
				"jti", tok.ID, "err", rerr)
			return capabilityCheckResult{
				agentID: tok.Subject,
				token:   tok,
				err:     capError("revocation store unavailable; token rejected (fail-closed)"),
			}
		case revoked:
			h.cfg.Metrics.ObserveRevocation("revoked", revDur)
			return capabilityCheckResult{
				agentID: tok.Subject,
				token:   tok,
				err:     capError("token revoked"),
			}
		default:
			h.cfg.Metrics.ObserveRevocation("not_revoked", revDur)
		}
	}

	if err := tok.Check(capability.RequestContext{
		AgentID: tok.Subject,
		Tool:    tool,
	}); err != nil {
		return capabilityCheckResult{agentID: tok.Subject, token: tok, err: err}
	}
	return capabilityCheckResult{agentID: tok.Subject, token: tok, summary: "ok"}
}

// runIntentCheck reads the X-Intent-Prompt header and asks the
// extractor for structured intent, then verifies the requested tool
// is permitted by that intent.
//
// Three outcome categories:
//
//   - Header present, extractor configured → call extractor, enforce.
//   - Header missing, RequireIntent false  → skip (dev mode default).
//   - Header missing, RequireIntent true   → fail closed.
//   - Extractor unconfigured               → skip (gateway in standalone mode).
func (h *mcpHandler) runIntentCheck(ctx context.Context, r *http.Request, tool, agentID string) intentCheckResult {
	prompt := r.Header.Get("X-Intent-Prompt")
	if prompt == "" {
		if h.cfg.RequireIntent {
			return intentCheckResult{err: errMissingIntent}
		}
		return intentCheckResult{summary: "skipped (no prompt header)"}
	}
	if h.cfg.Extractor == nil {
		if h.cfg.RequireIntent {
			return intentCheckResult{err: errExtractorNotConfigured}
		}
		h.cfg.Logger.Warn("intent header present but no extractor configured",
			"tool", tool,
			"hint", "set INTENTGATE_EXTRACTOR_URL to enable intent enforcement")
		return intentCheckResult{summary: "skipped (no extractor configured)"}
	}

	intent, err := h.cfg.Extractor.Extract(ctx, prompt, agentID)
	if err != nil {
		// Failing the extractor means we don't know the intent. Fail closed.
		return intentCheckResult{err: err}
	}
	ok, reason := intent.Allows(tool)
	if !ok {
		return intentCheckResult{intent: intent, err: capError(reason)}
	}
	return intentCheckResult{intent: intent, summary: "ok: " + reason}
}

// runPolicyCheck evaluates the Rego policy bundled into (or supplied to)
// the gateway. The policy sees the requested tool, its arguments, the
// agent ID from the verified capability token, and — when intent
// extraction ran — the extractor's structured output.
//
// When no engine is configured, the check is skipped (dev convenience).
// In production, main.go always supplies an engine: either a customer-
// authored policy from INTENTGATE_POLICY_FILE or the embedded default.
func (h *mcpHandler) runPolicyCheck(
	ctx context.Context,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
) policyCheckResult {
	if h.cfg.Policy == nil {
		return policyCheckResult{summary: "skipped (no policy engine)"}
	}

	in := policy.Input{
		Tool:    params.Name,
		Args:    params.Arguments,
		AgentID: cap.agentID,
	}
	if cap.agentID != "" {
		in.Capability = &policy.InputCap{Subject: cap.agentID}
	}
	if intent.intent != nil {
		in.Intent = &policy.InputIntent{
			Summary:        intent.intent.Summary,
			AllowedTools:   intent.intent.AllowedTools,
			ForbiddenTools: intent.intent.ForbiddenTools,
			Confidence:     intent.intent.Confidence,
		}
	}

	d, err := h.cfg.Policy.Evaluate(ctx, in)
	if err != nil {
		// Engine failure = fail closed.
		return policyCheckResult{err: err}
	}
	// Escalate beats both allow and block: a high-risk rule fired,
	// no autopilot. The mcp handler surfaces this to the approvals
	// queue and pauses.
	if d.Escalate {
		return policyCheckResult{
			escalate: true,
			reason:   d.Reason,
			summary:  "escalate: " + d.Reason,
		}
	}
	if !d.Allow {
		return policyCheckResult{err: capError(d.Reason)}
	}
	if d.Reason != "" {
		return policyCheckResult{summary: "ok: " + d.Reason}
	}
	return policyCheckResult{summary: "ok"}
}

// runBudgetCheck increments the per-token call counter and verifies
// the new total against any max_calls caveats present in the verified
// token.
//
// Behavior table:
//
//   - No verified token, RequireBudget=false → skipped (dev mode).
//   - No verified token, RequireBudget=true  → fail closed.
//   - Token present, no max_calls caveat     → allow without touching the store.
//   - Token present, max_calls exceeded      → deny with the strictest cap's reason.
//   - Token present, store nil but caveat ex → fail closed (operator misconfig).
func (h *mcpHandler) runBudgetCheck(ctx context.Context, cap capabilityCheckResult) budgetCheckResult {
	if cap.token == nil {
		if h.cfg.RequireBudget {
			return budgetCheckResult{err: errMissingBudgetToken}
		}
		return budgetCheckResult{summary: "skipped (no token)"}
	}
	d, err := budget.Check(ctx, h.cfg.Budget, cap.token)
	if err != nil {
		return budgetCheckResult{err: err}
	}
	if !d.Allowed {
		return budgetCheckResult{err: capError(d.Reason)}
	}
	if d.Used > 0 {
		return budgetCheckResult{summary: fmt.Sprintf("ok: %d call(s)", d.Used)}
	}
	return budgetCheckResult{summary: d.Reason}
}

// emitAudit builds and emits one audit event for the current request.
// Called exactly once per decision: at every block path and at the
// final allow path.
//
// The helper consolidates field gathering so each call site only has
// to specify what's specific to its decision (decision, check, reason).
// Everything else is plucked from the in-flight request and the
// partial check results.
func (h *mcpHandler) emitAudit(
	ctx context.Context,
	r *http.Request,
	params *mcp.ToolCallParams,
	cap capabilityCheckResult,
	intent intentCheckResult,
	decision audit.Decision,
	check audit.Check,
	reason string,
	start time.Time,
	upstreamStatus int,
) {
	if h.cfg.Audit == nil {
		return
	}

	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}

	e := audit.NewEvent(decision, params.Name)
	e.Check = check
	e.Reason = reason
	e.AgentID = cap.agentID
	e.ArgKeys = argKeys
	e.LatencyMS = time.Since(start).Milliseconds()
	e.RemoteIP = r.RemoteAddr
	e.UpstreamStatus = upstreamStatus

	if cap.token != nil {
		e.CapabilityTokenID = cap.token.ID
		e.RootCapabilityTokenID = cap.token.RootID
		e.CaveatCount = cap.token.CaveatCount()
	}
	if intent.intent != nil {
		e.IntentSummary = intent.intent.Summary
	}

	h.cfg.Audit.Emit(ctx, e)
}

// checkDecision maps a (err, summary) pair from one of the runX
// helpers to the bounded decision label used by Prometheus. Anything
// with a non-nil error is "block"; an empty summary is "skip"
// (the check was disabled / not applicable); otherwise "allow".
func checkDecision(err error, summary string) string {
	if err != nil {
		return "block"
	}
	if strings.HasPrefix(summary, "skipped") {
		return "skip"
	}
	return "allow"
}

// errMissingCapability is the static error returned when a token is
// required but absent.
var (
	errMissingCapability      = capError("capability token required (INTENTGATE_REQUIRE_CAPABILITY=true)")
	errMissingIntent          = capError("intent prompt required (INTENTGATE_REQUIRE_INTENT=true)")
	errExtractorNotConfigured = capError("intent prompt provided but no extractor URL is configured")
	errMissingBudgetToken     = capError("budget enforcement requires a verified capability token")
)

// capError is a tiny error type so we don't pull in fmt for one string.
type capError string

func (e capError) Error() string { return string(e) }

// write encodes a JSON-RPC response.
func (h *mcpHandler) write(w http.ResponseWriter, resp *mcp.Response) {
	if resp == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.cfg.Logger.Error("failed to encode mcp response", "err", err)
	}
}
