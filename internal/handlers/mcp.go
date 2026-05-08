package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/NetGnarus/intentgate-gateway-/internal/capability"
	"github.com/NetGnarus/intentgate-gateway-/internal/extractor"
	"github.com/NetGnarus/intentgate-gateway-/internal/mcp"
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
//  5. (Future) policy and budget checks.
//  6. Return the stub allow response.
func NewMCPHandler(cfg MCPHandlerConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
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
// stub allow result. Future sessions add policy and budget checks
// between intent and the stub allow.
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

	// Check 1: capability.
	capResult := h.runCapabilityCheck(r, params.Name)
	if capResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name,
			"check", "capability",
			"reason", capResult.err.Error(),
		)
		return mcp.NewErrorResponse(req.ID, mcp.CodeCapabilityFailed,
			"capability check failed", capResult.err.Error())
	}

	// Check 2: intent.
	intResult := h.runIntentCheck(ctx, r, params.Name, capResult.agentID)
	if intResult.err != nil {
		h.cfg.Logger.Info("mcp tools/call blocked",
			"tool", params.Name,
			"check", "intent",
			"agent", capResult.agentID,
			"reason", intResult.err.Error(),
		)
		return mcp.NewErrorResponse(req.ID, mcp.CodeIntentFailed,
			"intent check failed", intResult.err.Error())
	}

	// Argument values may contain sensitive data — log only the keys.
	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}
	h.cfg.Logger.Info("mcp tools/call",
		"tool", params.Name,
		"agent", capResult.agentID,
		"capability", capResult.summary,
		"intent", intResult.summary,
		"arg_keys", argKeys,
	)

	result := mcp.ToolCallResult{
		Content: []mcp.ContentBlock{{
			Type: "text",
			Text: "stub: pipeline not implemented; allow",
		}},
		IsError: false,
		IntentGate: &mcp.IntentGateMetadata{
			Decision:  "allow",
			Reason:    "stub: pipeline not implemented",
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

// capabilityCheckResult bundles what the capability stage learned.
type capabilityCheckResult struct {
	agentID string
	summary string
	err     error
}

// intentCheckResult bundles what the intent stage learned.
type intentCheckResult struct {
	summary string // short description ("ok: matched read_invoice", "skipped (no header)", ...)
	err     error
}

// runCapabilityCheck verifies the Bearer token's HMAC chain and
// evaluates its caveats against the requested tool.
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
	if err := tok.Check(capability.RequestContext{
		AgentID: tok.Subject,
		Tool:    tool,
	}); err != nil {
		return capabilityCheckResult{agentID: tok.Subject, err: err}
	}
	return capabilityCheckResult{agentID: tok.Subject, summary: "ok"}
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
		return intentCheckResult{err: capError(reason)}
	}
	return intentCheckResult{summary: "ok: " + reason}
}

// errMissingCapability is the static error returned when a token is
// required but absent.
var (
	errMissingCapability      = capError("capability token required (INTENTGATE_REQUIRE_CAPABILITY=true)")
	errMissingIntent          = capError("intent prompt required (INTENTGATE_REQUIRE_INTENT=true)")
	errExtractorNotConfigured = capError("intent prompt provided but no extractor URL is configured")
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
