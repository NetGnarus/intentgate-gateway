package mcp

import "encoding/json"

// MCP method names the gateway is aware of.
//
// In v0.1 only [MethodToolsCall] is handled. The others are recognized
// for logging but return MethodNotFound until upstream proxying lands in
// a later session.
const (
	MethodToolsCall  = "tools/call"
	MethodToolsList  = "tools/list"
	MethodInitialize = "initialize"
	MethodPing       = "ping"
)

// ToolCallParams is the params object for a tools/call request.
//
// Arguments is passed through to the upstream tool server unchanged. The
// gateway never logs the values (they may contain sensitive data); only
// the keys are logged for diagnostics.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolCallResult is the result object returned for a tools/call request.
//
// Content follows the MCP spec: a list of content blocks the LLM can
// interpret. IsError signals an in-tool error to the LLM (vs a transport
// error, which uses the JSON-RPC error envelope).
//
// IntentGate is a vendor extension carrying the gateway's decision
// metadata. Spec-compliant MCP clients ignore underscore-prefixed fields
// they don't recognize, so this is safe to include unconditionally.
type ToolCallResult struct {
	Content    []ContentBlock      `json:"content"`
	IsError    bool                `json:"isError"`
	IntentGate *IntentGateMetadata `json:"_intentgate,omitempty"`
}

// ContentBlock is one piece of MCP content. v0.1 emits only "text"
// blocks; "image", "resource", and other types are deferred until the
// gateway actually proxies upstream tool responses.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// IntentGateMetadata is the per-call decision summary the gateway
// attaches to every tools/call response under result._intentgate.
type IntentGateMetadata struct {
	// Decision is one of "allow", "block", or "escalate".
	Decision string `json:"decision"`
	// Reason is a short, human-readable explanation. May be empty.
	Reason string `json:"reason,omitempty"`
	// Check identifies which gate fired ("capability", "intent",
	// "policy", "budget"). Empty for "allow".
	Check string `json:"check,omitempty"`
	// LatencyMS is wall-clock time spent inside the gateway evaluating
	// this single request, in milliseconds.
	LatencyMS int64 `json:"latency_ms"`
}

// ParseToolCallParams decodes a tools/call params object from the raw
// JSON inside a Request.
func ParseToolCallParams(raw json.RawMessage) (*ToolCallParams, error) {
	var p ToolCallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ServerInfo identifies the MCP server in an initialize response. The
// gateway uses this when no upstream is configured so a stub-mode
// handshake still produces a valid initialize result.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult is the result object for a JSON-RPC initialize
// request. Returned by the gateway only when no upstream is configured;
// otherwise the upstream's initialize result is forwarded unchanged.
//
// ProtocolVersion follows the MCP spec's date-stamped versioning. The
// Capabilities map is intentionally typed as any so future MCP
// capability fields don't require gateway changes.
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Capabilities    map[string]any `json:"capabilities"`
}
