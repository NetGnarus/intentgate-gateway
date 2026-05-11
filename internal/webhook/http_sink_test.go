package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- happy path: signed POST + 200 ----------------------------

func TestHTTPSinkPostsSignedJSON(t *testing.T) {
	var receivedBody []byte
	var receivedSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type=%q", ct)
		}
		receivedSig = r.Header.Get("X-IntentGate-Signature")
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := []byte("test-secret-32bytes-long-enough!!")
	sink, err := NewHTTPSink(HTTPSinkConfig{
		URL:    srv.URL,
		Secret: secret,
	})
	if err != nil {
		t.Fatal(err)
	}

	ev := NewWebhookEvent(EventDeny, SeverityWarning)
	ev.Tool = "transfer_funds"
	ev.Tenant = "acme"
	ev.Reason = "above threshold"

	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	// Body round-trips.
	var got WebhookEvent
	if err := json.Unmarshal(receivedBody, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Tool != "transfer_funds" || got.Tenant != "acme" {
		t.Errorf("body lost fields: %+v", got)
	}

	// Signature is sha256=<hex(hmac(body, secret))>.
	if !strings.HasPrefix(receivedSig, "sha256=") {
		t.Fatalf("missing sha256= prefix: %q", receivedSig)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(receivedBody)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(receivedSig), []byte(expected)) {
		t.Errorf("signature mismatch: got %s want %s", receivedSig, expected)
	}

	if st := sink.Status(); st.TotalSent != 1 {
		t.Errorf("total_sent=%d want 1", st.TotalSent)
	}
}

// --- retry on 5xx --------------------------------------------

func TestHTTPSinkRetriesOn5xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPSinkConfig{
		URL:            srv.URL,
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Deliver(context.Background(), NewWebhookEvent(EventDeny, SeverityWarning)); err != nil {
		t.Fatalf("deliver after retry: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts=%d want 3", got)
	}
}

// --- 429 is retryable; 4xx (other) is not ---------------------

func TestHTTPSinkRetriesOn429(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink, _ := NewHTTPSink(HTTPSinkConfig{
		URL:            srv.URL,
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
	})
	if err := sink.Deliver(context.Background(), NewWebhookEvent(EventDeny, SeverityWarning)); err != nil {
		t.Fatalf("expected success after 429 retry, got %v", err)
	}
}

func TestHTTPSinkDoesNotRetryOn4xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "bad", http.StatusUnauthorized)
	}))
	defer srv.Close()

	sink, _ := NewHTTPSink(HTTPSinkConfig{
		URL:            srv.URL,
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
	})
	err := sink.Deliver(context.Background(), NewWebhookEvent(EventDeny, SeverityWarning))
	if err == nil {
		t.Fatalf("expected error on 401")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts=%d want 1 (4xx is not retried)", got)
	}
	if st := sink.Status(); st.TotalFailed != 1 {
		t.Errorf("total_failed=%d want 1", st.TotalFailed)
	}
}

// --- exhausted retries -> error -----------------------------

func TestHTTPSinkExhaustsRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	sink, _ := NewHTTPSink(HTTPSinkConfig{
		URL:            srv.URL,
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
	})
	err := sink.Deliver(context.Background(), NewWebhookEvent(EventDeny, SeverityWarning))
	if err == nil {
		t.Fatalf("expected error after exhausting retries")
	}
	if !strings.Contains(err.Error(), "all 3 attempts failed") {
		t.Errorf("error doesn't mention attempt count: %v", err)
	}
}

// --- no secret -> no signature header --------------------------

func TestHTTPSinkOmitsSignatureWhenNoSecret(t *testing.T) {
	var sigSeen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigSeen = r.Header.Get("X-IntentGate-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, _ := NewHTTPSink(HTTPSinkConfig{URL: srv.URL})
	_ = sink.Deliver(context.Background(), NewWebhookEvent(EventDeny, SeverityWarning))
	if sigSeen != "" {
		t.Errorf("expected no signature header, got %q", sigSeen)
	}
}

// --- ctx cancellation during backoff ----------------------------

func TestHTTPSinkRespectsCtxDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sink, _ := NewHTTPSink(HTTPSinkConfig{
		URL:            srv.URL,
		MaxRetries:     5,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := sink.Deliver(ctx, NewWebhookEvent(EventDeny, SeverityWarning))
	if err == nil {
		t.Fatalf("expected ctx cancellation error")
	}
}

// --- config validation -----------------------------------------

func TestHTTPSinkRequiresURL(t *testing.T) {
	if _, err := NewHTTPSink(HTTPSinkConfig{}); err == nil {
		t.Fatalf("expected error on empty URL")
	}
}

// --- secret parsing ----------------------------------------

func TestMustParseSecret(t *testing.T) {
	// Empty → nil, nil
	b, err := MustParseSecret("")
	if err != nil || b != nil {
		t.Errorf("empty: got (%v, %v)", b, err)
	}
	// Hex 64 chars → 32 bytes
	hexStr := strings.Repeat("ab", 32)
	b, err = MustParseSecret(hexStr)
	if err != nil || len(b) != 32 {
		t.Errorf("hex: got len=%d err=%v", len(b), err)
	}
	// Anything else: raw bytes
	b, err = MustParseSecret("not-hex-at-all")
	if err != nil || string(b) != "not-hex-at-all" {
		t.Errorf("raw: got %q err=%v", b, err)
	}
}
