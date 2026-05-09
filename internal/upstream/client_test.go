package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"id":"123"}}}`

const sampleSuccessResponse = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"invoice 123 has 2 line items"}],"isError":false}}`

const sampleJSONRPCErrorResponse = `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"db unavailable"}}`

func TestNew_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty url", Config{URL: ""}},
		{"bad scheme", Config{URL: "ftp://x"}},
		{"missing host", Config{URL: "http://"}},
		{"unparseable", Config{URL: "://"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("expected error for %+v, got client %+v", tc.cfg, c)
			}
		})
	}
}

func TestForward_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: want POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type: want application/json, got %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != sampleRequest {
			t.Errorf("body forwarded incorrectly:\n got: %s\nwant: %s", body, sampleRequest)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleSuccessResponse))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := c.Forward(context.Background(), []byte(sampleRequest))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.Status)
	}
	if string(resp.Body) != sampleSuccessResponse {
		t.Errorf("body: want %s, got %s", sampleSuccessResponse, resp.Body)
	}
}

// A 200 carrying a JSON-RPC error object is NOT a transport-level
// failure — the upstream answered, the answer just says no. The body
// is returned to the caller for pass-through.
func TestForward_UpstreamJSONRPCErrorIsNotAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleJSONRPCErrorResponse))
	}))
	defer srv.Close()

	c, _ := New(Config{URL: srv.URL})
	resp, err := c.Forward(context.Background(), []byte(sampleRequest))
	if err != nil {
		t.Fatalf("Forward unexpectedly errored: %v", err)
	}
	if !strings.Contains(string(resp.Body), `"code":-32000`) {
		t.Errorf("body missing upstream error: %s", resp.Body)
	}
}

func TestForward_NonOK_Returns_ErrUpstreamHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream busy"))
	}))
	defer srv.Close()

	c, _ := New(Config{URL: srv.URL})
	_, err := c.Forward(context.Background(), []byte(sampleRequest))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var uerr *Error
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *upstream.Error, got %T: %v", err, err)
	}
	if uerr.Kind != ErrUpstreamHTTP {
		t.Errorf("kind: want ErrUpstreamHTTP, got %s", uerr.Kind)
	}
	if uerr.Status != http.StatusServiceUnavailable {
		t.Errorf("status: want 503, got %d", uerr.Status)
	}
	if string(uerr.Body) != "upstream busy" {
		t.Errorf("body: want 'upstream busy', got %q", uerr.Body)
	}
}

func TestForward_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	c, _ := New(Config{URL: srv.URL, Timeout: 30 * time.Millisecond})
	_, err := c.Forward(context.Background(), []byte(sampleRequest))
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	var uerr *Error
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *upstream.Error, got %T: %v", err, err)
	}
	if uerr.Kind != ErrTimeout {
		t.Errorf("kind: want ErrTimeout, got %s (err: %v)", uerr.Kind, uerr)
	}
}

func TestForward_ContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	c, _ := New(Config{URL: srv.URL, Timeout: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := c.Forward(ctx, []byte(sampleRequest))
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	var uerr *Error
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *upstream.Error, got %T: %v", err, err)
	}
	if uerr.Kind != ErrTimeout {
		t.Errorf("kind: want ErrTimeout, got %s", uerr.Kind)
	}
}

func TestForward_TransportError(t *testing.T) {
	// Server that closes the connection without responding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Skip("http.Hijacker not supported in this test server")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	c, _ := New(Config{URL: srv.URL, Timeout: 1 * time.Second})
	_, err := c.Forward(context.Background(), []byte(sampleRequest))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var uerr *Error
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *upstream.Error, got %T: %v", err, err)
	}
	if uerr.Kind != ErrTransport {
		t.Errorf("kind: want ErrTransport, got %s", uerr.Kind)
	}
}

func TestForward_OversizedBody(t *testing.T) {
	huge := strings.Repeat("a", int(MaxBodyBytes+10))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(huge))
	}))
	defer srv.Close()

	c, _ := New(Config{URL: srv.URL})
	_, err := c.Forward(context.Background(), []byte(sampleRequest))
	if err == nil {
		t.Fatal("expected oversized-body error, got nil")
	}
	var uerr *Error
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *upstream.Error, got %T: %v", err, err)
	}
	if uerr.Kind != ErrUpstreamHTTP {
		t.Errorf("kind: want ErrUpstreamHTTP, got %s", uerr.Kind)
	}
}
