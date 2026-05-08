package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestValidate(t *testing.T) {
	cases := []struct {
		name    string
		req     Request
		wantErr bool
	}{
		{"valid", Request{JSONRPC: "2.0", Method: "tools/call"}, false},
		{"wrong version", Request{JSONRPC: "1.0", Method: "tools/call"}, true},
		{"missing version", Request{Method: "tools/call"}, true},
		{"empty method", Request{JSONRPC: "2.0"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestRequestIsNotification(t *testing.T) {
	withID := Request{JSONRPC: "2.0", Method: "x", ID: json.RawMessage(`1`)}
	if withID.IsNotification() {
		t.Errorf("request with id=1 should not be notification")
	}
	noID := Request{JSONRPC: "2.0", Method: "x"}
	if !noID.IsNotification() {
		t.Errorf("request without id should be notification")
	}
}

func TestRequestRoundTrip(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"id":"123"}}}`
	var req Request
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatal(err)
	}
	if req.JSONRPC != "2.0" {
		t.Errorf("jsonrpc=%q, want 2.0", req.JSONRPC)
	}
	if req.Method != "tools/call" {
		t.Errorf("method=%q, want tools/call", req.Method)
	}
	if string(req.ID) != "1" {
		t.Errorf("id=%s, want 1", req.ID)
	}

	params, err := ParseToolCallParams(req.Params)
	if err != nil {
		t.Fatal(err)
	}
	if params.Name != "read_invoice" {
		t.Errorf("name=%q, want read_invoice", params.Name)
	}
	if v, ok := params.Arguments["id"]; !ok || v != "123" {
		t.Errorf("arguments[id]=%v ok=%v, want '123' true", v, ok)
	}
}

func TestStringIDPreserved(t *testing.T) {
	// JSON-RPC 2.0 lets the id be a string; it must be echoed back as such.
	raw := `{"jsonrpc":"2.0","id":"abc-123","method":"ping"}`
	var req Request
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatal(err)
	}
	if string(req.ID) != `"abc-123"` {
		t.Errorf("id=%s, want \"abc-123\"", req.ID)
	}
}

func TestResultResponseShape(t *testing.T) {
	id := json.RawMessage(`42`)
	resp, err := NewResultResponse(id, ToolCallResult{
		Content: []ContentBlock{{Type: "text", Text: "hi"}},
		IntentGate: &IntentGateMetadata{
			Decision:  "allow",
			LatencyMS: 3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	for _, want := range []string{
		`"jsonrpc":"2.0"`,
		`"id":42`,
		`"result":`,
		`"_intentgate":`,
		`"decision":"allow"`,
		`"latency_ms":3`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("response missing %q in: %s", want, s)
		}
	}
	if strings.Contains(s, `"error":`) {
		t.Errorf("unexpected error field on success response: %s", s)
	}
}

func TestErrorResponseUsesNullForMissingID(t *testing.T) {
	// Parse-error responses must use id=null per spec.
	resp := NewErrorResponse(nil, CodeParseError, "bad json", nil)
	out, _ := json.Marshal(resp)
	s := string(out)
	if !strings.Contains(s, `"id":null`) {
		t.Errorf("expected id:null, got %s", s)
	}
	if !strings.Contains(s, `"code":-32700`) {
		t.Errorf("expected code:-32700, got %s", s)
	}
	if strings.Contains(s, `"result":`) {
		t.Errorf("unexpected result field on error response: %s", s)
	}
}

func TestErrorResponsePreservesID(t *testing.T) {
	id := json.RawMessage(`"abc-123"`)
	resp := NewErrorResponse(id, CodeInvalidParams, "no", "missing name")
	out, _ := json.Marshal(resp)
	s := string(out)
	if !strings.Contains(s, `"id":"abc-123"`) {
		t.Errorf("expected id:\"abc-123\", got %s", s)
	}
	if !strings.Contains(s, `"code":-32602`) {
		t.Errorf("expected code:-32602, got %s", s)
	}
	if !strings.Contains(s, `"data":"missing name"`) {
		t.Errorf("expected data carried through, got %s", s)
	}
}

func TestParseToolCallParamsInvalidJSON(t *testing.T) {
	_, err := ParseToolCallParams(json.RawMessage("not-json"))
	if err == nil {
		t.Fatalf("expected error parsing invalid JSON")
	}
}

func TestParseToolCallParamsEmpty(t *testing.T) {
	// An empty params is allowed at parse time; the handler will reject
	// based on Name being empty.
	p, err := ParseToolCallParams(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "" {
		t.Errorf("expected empty name, got %q", p.Name)
	}
}
