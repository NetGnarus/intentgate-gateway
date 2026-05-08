// Package mcp implements the JSON-RPC 2.0 envelope used by Model Context
// Protocol clients and servers.
//
// The gateway accepts MCP requests on POST /v1/mcp. Inbound requests are
// parsed with [Request], validated with [Request.Validate], and responses
// are built with [NewResultResponse] or [NewErrorResponse]. The gateway's
// per-call decision metadata travels in the result under the underscore-
// prefixed `_intentgate` field, which spec-compliant MCP clients ignore.
package mcp

import (
	"encoding/json"
	"errors"
)

// Version is the JSON-RPC protocol version this implementation speaks.
const Version = "2.0"

// Request is the inbound JSON-RPC 2.0 request envelope.
//
// ID is kept as json.RawMessage because per spec it may be a string, a
// number, or null — clients must echo whatever they receive.
//
// An empty ID (omitted by the client) marks the request as a notification
// per JSON-RPC 2.0; the server must not send a response for those.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether this request is a JSON-RPC notification.
// Notifications carry no id and must receive no response.
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0
}

// Validate checks the request against minimum JSON-RPC 2.0 requirements.
// A non-nil error from Validate should be turned into an InvalidRequest
// response by the caller.
func (r *Request) Validate() error {
	if r.JSONRPC != Version {
		return errors.New(`"jsonrpc" field must be "2.0"`)
	}
	if r.Method == "" {
		return errors.New(`"method" field is required`)
	}
	return nil
}

// Response is the outbound JSON-RPC 2.0 response envelope.
//
// Exactly one of Result or Error is populated on a well-formed response.
// ID echoes the request's ID, or is null if the request couldn't be
// parsed far enough to recover an ID (parse errors).
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
}

// ResponseError is the error object embedded in a JSON-RPC 2.0 error
// response. Code values follow https://www.jsonrpc.org/specification#error_object.
type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 error codes.
//
// See https://www.jsonrpc.org/specification#error_object for definitions.
const (
	CodeParseError     = -32700 // Invalid JSON was received by the server.
	CodeInvalidRequest = -32600 // The JSON sent is not a valid Request object.
	CodeMethodNotFound = -32601 // The method does not exist / is not available.
	CodeInvalidParams  = -32602 // Invalid method parameter(s).
	CodeInternalError  = -32603 // Internal JSON-RPC error.
)

// IntentGate-specific server error codes.
//
// JSON-RPC 2.0 reserves -32000 to -32099 for implementation-defined server
// errors; we use a contiguous slice from -32010 onward so each gateway
// check has a stable, distinguishable code.
const (
	CodeCapabilityFailed = -32010 // Capability check failed (token, scope, attenuation).
	CodeIntentFailed     = -32011 // Intent check failed (call not in declared intent).
	CodePolicyFailed     = -32012 // Policy check failed (OPA denied).
	CodeBudgetFailed     = -32013 // Budget or taint check failed.
)

// NewErrorResponse builds a JSON-RPC 2.0 error response.
//
// If id is empty (parse-error case), the response id will be null per spec.
func NewErrorResponse(id json.RawMessage, code int, message string, data any) *Response {
	return &Response{
		JSONRPC: Version,
		ID:      idOrNull(id),
		Error: &ResponseError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// NewResultResponse builds a JSON-RPC 2.0 success response.
//
// The result argument is marshaled to JSON and stored in Response.Result.
// An error from json.Marshal is returned to the caller, who should turn
// it into a CodeInternalError response.
func NewResultResponse(id json.RawMessage, result any) (*Response, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Response{
		JSONRPC: Version,
		ID:      idOrNull(id),
		Result:  encoded,
	}, nil
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}
