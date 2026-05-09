// Package upstream forwards authorized MCP tool calls to a downstream
// MCP / JSON-RPC tool server (the "real" server the agent ultimately
// wants to talk to) and translates the response back to the caller.
//
// The four-check authorization pipeline (capability, intent, policy,
// budget) decides whether a call is permitted; this package handles
// the delivery of permitted calls.
//
// # Wire shape
//
// The gateway forwards the exact JSON-RPC request body it received,
// preserving the client's id and params so the upstream's response
// can be returned to the client unchanged. The upstream is expected
// to speak JSON-RPC 2.0 / MCP — same shape as /v1/mcp.
//
// # Failure modes
//
// Forward returns a typed *Error so the caller can distinguish:
//
//   - [ErrTimeout]      — context deadline or http.Client timeout.
//   - [ErrTransport]    — network failure, DNS, connection refused, ...
//   - [ErrUpstreamHTTP] — upstream returned a non-2xx status.
//
// Operational failures all count as gateway-level blocks for audit
// purposes (the authorized call did not complete). Upstream JSON-RPC
// errors (a 200-OK response carrying an error object) are NOT failures
// here — they're returned in [Response.Body] for the caller to pass
// through to the client.
package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DefaultTimeout is used when [Config.Timeout] is unset.
const DefaultTimeout = 30 * time.Second

// MaxBodyBytes caps the upstream response we'll read into memory. The
// gateway is a pass-through, not a proxy of arbitrary-size data; tool
// outputs in v0.1 are short JSON. Bumping this without thought
// invites OOM under hostile upstreams.
const MaxBodyBytes = 1 << 20 // 1 MiB

// Config configures a Client.
type Config struct {
	// URL is the upstream MCP endpoint, e.g. "http://tools.internal:9000/mcp".
	// Required.
	URL string
	// Timeout caps end-to-end forward duration (connection + request +
	// response read). Zero or negative selects [DefaultTimeout].
	Timeout time.Duration
	// HTTPClient is the underlying client. Optional; one is constructed
	// from Timeout when nil. Tests inject a custom client to point at an
	// httptest.Server.
	HTTPClient *http.Client
}

// Client is a configured connection to a single upstream MCP server.
//
// Client is safe for concurrent use.
type Client struct {
	url  string
	http *http.Client
}

// New constructs a Client. Returns an error when cfg.URL is empty or
// not a parseable absolute http(s) URL.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("upstream: URL is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("upstream: parse URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("upstream: URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("upstream: URL must include a host")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Client{url: cfg.URL, http: httpClient}, nil
}

// Response is the raw upstream reply.
//
// Body is the unmodified upstream JSON-RPC response. The caller is
// responsible for parsing it and merging in any vendor-extension
// metadata before returning it to the client.
type Response struct {
	Status int
	Body   []byte
}

// Forward POSTs body to the upstream and returns the response or a
// typed *Error.
//
// body must be a valid JSON-RPC 2.0 request — Forward does not parse
// or modify it. Pass the same bytes the gateway received from the
// client (re-serialized from the parsed envelope is fine; the agent's
// id round-trips faithfully either way).
func (c *Client) Forward(ctx context.Context, body []byte) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Kind: ErrTransport, cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &Error{Kind: ErrTimeout, cause: err}
		}
		return nil, &Error{Kind: ErrTransport, cause: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, &Error{Kind: ErrTransport, cause: err, Status: resp.StatusCode}
	}
	if int64(len(raw)) > MaxBodyBytes {
		return nil, &Error{
			Kind:   ErrUpstreamHTTP,
			cause:  fmt.Errorf("upstream body exceeded %d bytes", MaxBodyBytes),
			Status: resp.StatusCode,
		}
	}

	if resp.StatusCode >= 400 {
		return nil, &Error{
			Kind:   ErrUpstreamHTTP,
			cause:  fmt.Errorf("upstream HTTP %d", resp.StatusCode),
			Status: resp.StatusCode,
			Body:   raw,
		}
	}

	return &Response{Status: resp.StatusCode, Body: raw}, nil
}

// ErrorKind enumerates operational failure modes Forward distinguishes.
type ErrorKind int

const (
	// ErrTransport is any network-layer or wrapping failure that wasn't
	// a timeout: DNS, connection refused, TLS handshake, body read.
	ErrTransport ErrorKind = iota
	// ErrTimeout is a context-deadline or http.Client timeout.
	ErrTimeout
	// ErrUpstreamHTTP is a non-2xx response from the upstream.
	ErrUpstreamHTTP
)

// String returns a short stable identifier suitable for logs and audit.
func (k ErrorKind) String() string {
	switch k {
	case ErrTransport:
		return "transport"
	case ErrTimeout:
		return "timeout"
	case ErrUpstreamHTTP:
		return "upstream_http"
	default:
		return "unknown"
	}
}

// Error is the typed failure returned from Forward.
//
// Callers can use errors.As to recover the kind:
//
//	var uerr *upstream.Error
//	if errors.As(err, &uerr) && uerr.Kind == upstream.ErrTimeout { ... }
type Error struct {
	Kind ErrorKind
	// Status is the upstream HTTP status when known (set for ErrUpstreamHTTP,
	// may be set for ErrTransport when the failure happened post-headers).
	Status int
	// Body is the upstream's response body when Kind is ErrUpstreamHTTP.
	// Capped at MaxBodyBytes. May be nil for other kinds.
	Body []byte

	cause error
}

// Error implements the error interface with a short, audit-friendly message.
func (e *Error) Error() string {
	switch e.Kind {
	case ErrTimeout:
		return "upstream timeout: " + e.cause.Error()
	case ErrTransport:
		if e.Status > 0 {
			return fmt.Sprintf("upstream transport error after HTTP %d: %s", e.Status, e.cause)
		}
		return "upstream transport error: " + e.cause.Error()
	case ErrUpstreamHTTP:
		return fmt.Sprintf("upstream HTTP %d", e.Status)
	default:
		if e.cause != nil {
			return e.cause.Error()
		}
		return "upstream error"
	}
}

// Unwrap returns the underlying cause, allowing errors.Is / errors.As
// against transport-layer errors (e.g. net.OpError, context.DeadlineExceeded).
func (e *Error) Unwrap() error { return e.cause }

// isTimeout returns true if err is a net-package timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
