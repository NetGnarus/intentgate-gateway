package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Decision is the gateway's verdict on a tool call.
//
// In the four-check pipeline (capability → intent → policy → budget) any
// check can short-circuit to "block" or "escalate". When all checks pass,
// the gateway forwards the call upstream and returns "allow" with the
// tool server's response in Result.
type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionBlock    Decision = "block"
	DecisionEscalate Decision = "escalate"
)

// ToolCallRequest is the inbound request shape for /v1/tool-call.
//
// This is a deliberately simple JSON shape for v0.1. Full MCP / JSON-RPC
// framing comes in session 2 — this skeleton accepts a flat JSON payload
// so we can curl against it immediately.
type ToolCallRequest struct {
	// Tool is the upstream tool the agent is asking to invoke
	// (e.g. "read_invoice", "send_email").
	Tool string `json:"tool"`
	// Args are passed through to the upstream tool. The gateway does not
	// interpret them in v0.1 beyond logging the keys.
	Args map[string]any `json:"args,omitempty"`
	// AgentID identifies the calling agent (e.g. "finance-copilot-v3").
	AgentID string `json:"agent_id,omitempty"`
	// SessionID groups related calls within one user-driven session.
	SessionID string `json:"session_id,omitempty"`
	// IntentToken is the capability/intent token issued when the user
	// declared their intent. Verified by the policy engine in later sessions.
	IntentToken string `json:"intent_token,omitempty"`
}

// ToolCallResponse is the outbound response shape for /v1/tool-call.
type ToolCallResponse struct {
	Decision  Decision       `json:"decision"`
	Result    map[string]any `json:"result,omitempty"` // populated on allow (passthrough)
	Reason    string         `json:"reason,omitempty"` // populated on block/escalate
	Check     string         `json:"check,omitempty"`  // capability|intent|policy|budget
	LatencyMS int64          `json:"latency_ms"`
}

type toolCallHandler struct {
	log *slog.Logger
}

// NewToolCallHandler returns the HTTP handler for POST /v1/tool-call.
//
// In v0.1 this is a stub: it parses the request, logs it, and returns a
// fixed "allow" decision so the rest of the system can be exercised
// end-to-end. The four-check pipeline (capability → intent → policy →
// budget) lands in subsequent sessions.
func NewToolCallHandler(log *slog.Logger) http.Handler {
	return &toolCallHandler{log: log}
}

func (h *toolCallHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json")

	// Cap request bodies at 1 MiB. Tool-call payloads should be small;
	// anything larger is almost certainly abuse.
	const maxBody = 1 << 20
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_body_failed", err)
		return
	}

	var req ToolCallRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err)
		return
	}
	if req.Tool == "" {
		writeError(w, http.StatusBadRequest, "missing_tool",
			errors.New("tool field is required"))
		return
	}

	// Collect arg keys (not values) for logging — we never log full args
	// because they may contain sensitive data.
	argKeys := make([]string, 0, len(req.Args))
	for k := range req.Args {
		argKeys = append(argKeys, k)
	}

	h.log.Info("tool call received",
		"tool", req.Tool,
		"agent_id", req.AgentID,
		"session_id", req.SessionID,
		"arg_keys", argKeys,
		"has_intent_token", req.IntentToken != "",
	)

	// STUB: until the four-check pipeline lands, every well-formed call
	// is allowed. Real evaluation order will be:
	//   1. capability  — token signature, scope, attenuation chain
	//   2. intent      — call matches user's declared intent
	//   3. policy      — OPA evaluates against bundled policy
	//   4. budget      — call/cost/duration counters within limits
	resp := ToolCallResponse{
		Decision:  DecisionAllow,
		Reason:    "stub: pipeline not implemented",
		LatencyMS: time.Since(start).Milliseconds(),
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Error("failed to encode tool-call response", "err", err)
	}
}

// writeError writes a small JSON error body and the given status code.
func writeError(w http.ResponseWriter, status int, code string, err error) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  code,
		"detail": err.Error(),
	})
}
