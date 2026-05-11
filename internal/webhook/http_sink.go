package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// HTTPSinkConfig configures an HTTP webhook sink.
type HTTPSinkConfig struct {
	// URL is the receiver endpoint. Required.
	URL string
	// Secret is the HMAC-SHA256 key used to sign the request body.
	// When empty, no signature header is emitted — leave empty only
	// for trusted receivers on an internal network. Production
	// deployments should always set this.
	Secret []byte
	// HTTPClient is injected in tests; nil falls back to a default
	// client with a 10-second per-attempt timeout.
	HTTPClient *http.Client
	// MaxRetries is the number of retry attempts on retryable
	// failures (5xx, 429, transport error). 0 → 3 retries (4 total
	// attempts).
	MaxRetries int
	// InitialBackoff is the first retry delay; subsequent delays
	// double up to MaxBackoff. 0 → 500 ms.
	InitialBackoff time.Duration
	// MaxBackoff caps the per-attempt delay. 0 → 5 s.
	MaxBackoff time.Duration
	// Logger receives delivery / retry / drop notices.
	Logger *slog.Logger
}

// HTTPSink POSTs each WebhookEvent as a JSON body to a configured
// endpoint, signing the body with HMAC-SHA256 under [Secret]. Retries
// retryable failures with exponential backoff up to MaxRetries.
//
// # Signature header
//
// The receiver verifies the body with:
//
//	X-IntentGate-Signature: sha256=<hex(hmac_sha256(body, secret))>
//
// Same shape as GitHub webhook signatures, so a stock Slack-app /
// Probot-style verifier works out of the box. Receivers MUST compare
// in constant time; a leaked secret defeats authentication, so
// rotate via INTENTGATE_WEBHOOK_SECRET when an operator leaves.
type HTTPSink struct {
	cfg         HTTPSinkConfig
	totalSent   atomic.Uint64
	totalFailed atomic.Uint64
}

const (
	defaultMaxRetries     = 3
	defaultInitialBackoff = 500 * time.Millisecond
	defaultMaxBackoff     = 5 * time.Second
	httpAttemptTimeout    = 10 * time.Second
)

// NewHTTPSink validates config and returns a ready sink. Returns
// an error rather than a half-configured sink so the gateway fails
// fast at startup.
func NewHTTPSink(cfg HTTPSinkConfig) (*HTTPSink, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("webhook: URL is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: httpAttemptTimeout}
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaultInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &HTTPSink{cfg: cfg}, nil
}

// Deliver POSTs the event with retries on retryable failures. Returns
// the LAST error if every attempt failed, nil on first success.
func (s *HTTPSink) Deliver(ctx context.Context, ev WebhookEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		// Marshal failure isn't retryable; record and return.
		s.totalFailed.Add(1)
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	var lastErr error
	delay := s.cfg.InitialBackoff
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retrying, honoring ctx cancellation.
			select {
			case <-ctx.Done():
				s.totalFailed.Add(1)
				return fmt.Errorf("webhook: cancelled during backoff: %w", ctx.Err())
			case <-time.After(delay):
			}
			delay *= 2
			if delay > s.cfg.MaxBackoff {
				delay = s.cfg.MaxBackoff
			}
		}

		err := s.attempt(ctx, body)
		if err == nil {
			s.totalSent.Add(1)
			return nil
		}
		lastErr = err
		if !retryable(err) {
			s.cfg.Logger.Warn("webhook: non-retryable delivery failure; not retrying",
				"err", err.Error(),
				"url", s.cfg.URL,
				"event", string(ev.Event),
			)
			s.totalFailed.Add(1)
			return err
		}
		s.cfg.Logger.Info("webhook: retryable failure",
			"attempt", attempt+1,
			"max", s.cfg.MaxRetries+1,
			"err", err.Error(),
			"next_delay_ms", delay.Milliseconds(),
		)
	}
	s.totalFailed.Add(1)
	return fmt.Errorf("webhook: all %d attempts failed: %w", s.cfg.MaxRetries+1, lastErr)
}

// attempt is one POST. Returns a retryableError on 5xx/429 or
// transport failure; a non-retryable error otherwise.
func (s *HTTPSink) attempt(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "intentgate-gateway/webhook")
	if len(s.cfg.Secret) > 0 {
		mac := hmac.New(sha256.New, s.cfg.Secret)
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-IntentGate-Signature", "sha256="+sig)
	}

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return &retryableErr{wrapped: err}
	}
	defer func() {
		// Drain so the connection can be reused. Cap at 4 KiB —
		// receivers shouldn't be sending megabytes of response.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	httpErr := fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyPreview)))
	// 429 + 5xx retryable; 4xx (auth, malformed) is not.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return &retryableErr{wrapped: httpErr}
	}
	return httpErr
}

// Status returns a snapshot of the sink's delivery counters for the
// admin endpoint. Mirrors the SIEM Status shape so the console can
// render webhook + SIEM cards in one list.
type Status struct {
	Name        string `json:"name"`
	Configured  bool   `json:"configured"`
	Endpoint    string `json:"endpoint,omitempty"`
	TotalSent   uint64 `json:"total_events"`
	TotalFailed uint64 `json:"dropped_count"`
	LastError   string `json:"last_error,omitempty"`
}

// Status snapshots the counters.
func (s *HTTPSink) Status() Status {
	return Status{
		Name:        "webhook",
		Configured:  true,
		Endpoint:    s.cfg.URL,
		TotalSent:   s.totalSent.Load(),
		TotalFailed: s.totalFailed.Load(),
	}
}

// MaxRetries exposes the configured retry budget; useful in tests
// and for the admin endpoint's "current configuration" view.
func (s *HTTPSink) MaxRetries() int { return s.cfg.MaxRetries }

// retryableErr is the marker type used to distinguish "try again"
// from "give up" failures inside the worker. Receivers don't see
// this type — Deliver returns it as a plain error on the final
// attempt.
type retryableErr struct{ wrapped error }

func (e *retryableErr) Error() string {
	if e.wrapped == nil {
		return "retryable: <nil>"
	}
	return "retryable: " + e.wrapped.Error()
}

func (e *retryableErr) Unwrap() error { return e.wrapped }

func retryable(err error) bool {
	var r *retryableErr
	return errors.As(err, &r)
}

// MustParseSecret is a convenience for env-var parsing in main.go:
// hex / base64 / raw. Returns empty when the input is empty (which
// disables the signature header), an error on a malformed input.
func MustParseSecret(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	// Hex (64 chars) → 32 bytes.
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	// Anything else: use the raw bytes. HMAC accepts any key length;
	// 32+ bytes is recommended. We don't fight the operator over
	// the encoding — they pick what they paste.
	return []byte(raw), nil
}

// formatStatusCode is a small helper used by tests to assert error
// messages without coupling to net/http's exact string. Not used by
// production code; exported in this file's package scope.
func formatStatusCode(code int) string { //nolint:unused
	return "HTTP " + strconv.Itoa(code)
}
