package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/NetGnarus/intentgate-gateway-/internal/mcp"
)

// mcpHandler serves POST /v1/mcp, the JSON-RPC 2.0 endpoint clients use
// to send Model Context Protocol traffic at the gateway.
type mcpHandler struct {
	log *slog.Logger
}

// NewMCPHandler returns the HTTP handler for POST /v1/mcp.
//
// In v0.1 only the "tools/call" method is implemented. Other MCP methods
// (tools/list, initialize, ping) return JSON-RPC MethodNotFound until
// upstream-server proxying lands in a later session.
//
// The gateway does not yet evaluate the four-check pipeline; every
// well-formed tools/call gets decision="allow" with stub metadata.
func NewMCPHandler(log *slog.Logger) http.Handler {
	return &mcpHandler{log: log}
}

func (h *mcpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Cap inbound bodies. Tool-call payloads should be small.
	const maxBody = 1 << 20
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		// Per JSON-RPC 2.0, a parse error responds with id=null since we
		// can't safely recover the client's id.
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
		resp := h.handleToolsCall(&req)
		if notification {
			// Spec: notifications get no response.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, resp)

	default:
		h.log.Info("mcp method not implemented",
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

// handleToolsCall is the gateway's stub tools/call implementation.
//
// Real evaluation order (capability → intent → policy → budget) lands
// in session 3+. For now: parse params, log, return a stub allow.
func (h *mcpHandler) handleToolsCall(req *mcp.Request) *mcp.Response {
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

	// Argument values may be sensitive — log only the keys.
	argKeys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		argKeys = append(argKeys, k)
	}
	h.log.Info("mcp tools/call",
		"tool", params.Name,
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

// write encodes a JSON-RPC response. If encoding fails after the response
// has already been started, there is nothing useful we can do for the
// client beyond logging.
func (h *mcpHandler) write(w http.ResponseWriter, resp *mcp.Response) {
	if resp == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Error("failed to encode mcp response", "err", err)
	}
}
