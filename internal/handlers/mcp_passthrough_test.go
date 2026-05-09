package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/mcp"
	"github.com/NetGnarus/intentgate-gateway/internal/upstream"
)

// passthroughTest spins up an upstream httptest.Server (when needed)
// and the MCP handler, posts a JSON-RPC request, and returns the
// parsed response. Keeps the tests below focused on assertions.
func passthroughTest(
	t *testing.T,
	method string,
	upstreamHandler http.HandlerFunc,
	requestParams any,
) *mcp.Response {
	t.Helper()

	cfg := MCPHandlerConfig{}
	if upstreamHandler != nil {
		srv := httptest.NewServer(upstreamHandler)
		t.Cleanup(srv.Close)
		c, err := upstream.New(upstream.Config{URL: srv.URL})
		if err != nil {
			t.Fatalf("upstream.New: %v", err)
		}
		cfg.Upstream = c
	}

	h := NewMCPHandler(cfg)

	rid := json.RawMessage("1")
	var paramsRaw json.RawMessage
	if requestParams != nil {
		raw, err := json.Marshal(requestParams)
		if err != nil {
			t.Fatalf("marshal params: %v", err)
		}
		paramsRaw = raw
	}
	body, _ := json.Marshal(mcp.Request{
		JSONRPC: mcp.Version,
		ID:      rid,
		Method:  method,
		Params:  paramsRaw,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, rec.Body.String())
	}
	return &resp
}

// --- forwarded paths -------------------------------------------------

func TestPassthrough_ToolsList_ForwardsToUpstream(t *testing.T) {
	called := false
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"method":"tools/list"`) {
			t.Errorf("upstream got wrong body: %s", body)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_invoice"},{"name":"send_email"}]}}`))
	}

	resp := passthroughTest(t, mcp.MethodToolsList, upstreamHandler, nil)
	if !called {
		t.Fatal("upstream was not called")
	}
	if resp.Error != nil {
		t.Fatalf("expected result, got error: %+v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), `"read_invoice"`) {
		t.Errorf("upstream tools list not propagated: %s", resp.Result)
	}
	// Discovery responses MUST NOT carry _intentgate metadata —
	// authorization extension is reserved for tools/call.
	if strings.Contains(string(resp.Result), `"_intentgate"`) {
		t.Errorf("tools/list response should not carry _intentgate metadata: %s", resp.Result)
	}
}

func TestPassthrough_Initialize_ForwardsToUpstream(t *testing.T) {
	upstreamHandler := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"upstream-srv","version":"9.9"},"capabilities":{"tools":{}}}}`))
	}

	resp := passthroughTest(t, mcp.MethodInitialize, upstreamHandler, nil)
	if resp.Error != nil {
		t.Fatalf("expected result, got error: %+v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), `"upstream-srv"`) {
		t.Errorf("upstream serverInfo not forwarded: %s", resp.Result)
	}
}

func TestPassthrough_Ping_ForwardsToUpstream(t *testing.T) {
	upstreamHandler := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}

	resp := passthroughTest(t, mcp.MethodPing, upstreamHandler, nil)
	if resp.Error != nil {
		t.Fatalf("expected result, got error: %+v", resp.Error)
	}
}

// --- local fallback paths -------------------------------------------

func TestPassthrough_Initialize_LocalFallbackWhenNoUpstream(t *testing.T) {
	resp := passthroughTest(t, mcp.MethodInitialize, nil, nil)
	if resp.Error != nil {
		t.Fatalf("expected result, got error: %+v", resp.Error)
	}
	var got mcp.InitializeResult
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.ServerInfo.Name != "intentgate" {
		t.Errorf("serverInfo.name: want intentgate, got %q", got.ServerInfo.Name)
	}
	if got.ProtocolVersion == "" {
		t.Error("protocolVersion is empty")
	}
}

func TestPassthrough_ToolsList_LocalFallbackReturnsEmptyList(t *testing.T) {
	resp := passthroughTest(t, mcp.MethodToolsList, nil, nil)
	if resp.Error != nil {
		t.Fatalf("expected result, got error: %+v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), `"tools":[]`) {
		t.Errorf("expected empty tools list, got: %s", resp.Result)
	}
}

func TestPassthrough_Ping_LocalFallbackReturnsEmptyResult(t *testing.T) {
	resp := passthroughTest(t, mcp.MethodPing, nil, nil)
	if resp.Error != nil {
		t.Fatalf("expected result, got error: %+v", resp.Error)
	}
	if string(resp.Result) != `{}` {
		t.Errorf("expected empty result {}, got: %s", resp.Result)
	}
}

// --- error paths ----------------------------------------------------

func TestPassthrough_Upstream5xx_ReturnsInternalError(t *testing.T) {
	upstreamHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream busy"))
	}

	resp := passthroughTest(t, mcp.MethodToolsList, upstreamHandler, nil)
	if resp.Error == nil {
		t.Fatalf("expected error, got result: %s", resp.Result)
	}
	if resp.Error.Code != mcp.CodeInternalError {
		t.Errorf("error code: want %d, got %d", mcp.CodeInternalError, resp.Error.Code)
	}
	// The data field should carry upstream_status so SOC analysts can
	// distinguish gateway-blocked from upstream-broken without parsing
	// free-text reasons.
	dataMap, ok := resp.Error.Data.(map[string]any)
	if !ok {
		t.Fatalf("error.data: want map, got %T (%v)", resp.Error.Data, resp.Error.Data)
	}
	if status := int(dataMap["upstream_status"].(float64)); status != http.StatusServiceUnavailable {
		t.Errorf("upstream_status: want 503, got %d", status)
	}
}

// --- sanity: unknown method still hits the default branch -----------

func TestPassthrough_UnknownMethodStillReturnsMethodNotFound(t *testing.T) {
	resp := passthroughTest(t, "totally/unknown", nil, nil)
	if resp.Error == nil {
		t.Fatalf("expected error, got result: %s", resp.Result)
	}
	if resp.Error.Code != mcp.CodeMethodNotFound {
		t.Errorf("error code: want %d, got %d", mcp.CodeMethodNotFound, resp.Error.Code)
	}
}
