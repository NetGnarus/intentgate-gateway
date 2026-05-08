package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/NetGnarus/intentgate-gateway-/internal/capability"
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
}

type mcpHandler struct {
	cfg MCPHandlerConfig
}

// NewMCPHandler returns the HTTP handler for POST /v1/mcp.
//
// In v0.1 only the "tools/call" method is implemented. Other MCP methods
// (tools/list, initialize, ping) return JSON-RPC MethodNotFound until
// upstream-server proxying lands in a later session.
//
// Capability check (first of four). If a Bearer token is supplied, the
// handler verifies its signature under MasterKey and evaluates the
// caveat chain against the request. Failures return JSON-RPC error
// CodeCapabilityFailed (-32010). The other three checks (intent,
// policy, budget) land in subsequent sessions.
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
		resp := h.handleToolsCall(&req, r)
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

// handleToolsCall runs the (currently only) capability check, then
// returns the stub allow result. Future sessions add intent, policy,
// and budget checks between capability and the stub allow.
func (h *mcpHandler) handleToolsCall(req *mcp.Request, r *http.Request) *mcp.Response {
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

	// Capability check: verify the Bearer token (if any) and evaluate
	// its caveats against the requested tool.
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

	// Argument values may contain sensitive data — log only the keys.
	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}
	h.cfg.Logger.Info("mcp tools/call",
		"tool", params.Name,
		"agent", capResult.agentID,
		"capability", capResult.summary,
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

// capabilityCheckResult bundles what the capability stage learned about
// the request so the remaining handler can log/decide accordingly.
type capabilityCheckResult struct {
	agentID string // empty if no token was supplied
	summary string // short audit string ("ok", "skipped (no token)", ...)
	err     error  // non-nil = check failed; handler must reject
}

// runCapabilityCheck inspects the Authorization header, verifies the
// Bearer token under the master key (if any), and evaluates its caveats
// against the requested tool name.
//
// Three outcome categories:
//
//   - Token present and valid → result.err == nil, agentID = token.Subject
//   - Token absent and not required → result.err == nil, summary "skipped"
//   - Token absent and required, OR token invalid → result.err non-nil
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

// errMissingCapability is the static error returned when a token is
// required but absent. Defined as a package var for cheap equality
// checks in tests.
var errMissingCapability = capError("capability token required (INTENTGATE_REQUIRE_CAPABILITY=true)")

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
