package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// SplunkConfig configures a Splunk HTTP Event Collector emitter.
type SplunkConfig struct {
	// URL is the HEC endpoint, e.g. "https://splunk.example.com:8088/services/collector".
	// Required.
	URL string
	// Token is the HEC token, sent as "Authorization: Splunk <token>".
	// Required.
	Token string
	// Index is the optional Splunk index name. When empty, Splunk
	// routes events to the token's default index.
	Index string
	// Source / Sourcetype let the operator override Splunk's
	// metadata tagging. Defaults: source="intentgate", sourcetype="_json".
	Source     string
	Sourcetype string
	// HTTPClient is injected in tests; nil falls back to a default
	// client with a 30-second total timeout.
	HTTPClient *http.Client
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// SplunkEmitter ships audit events to a Splunk HEC endpoint.
//
// Each batched flush is one HTTP POST containing newline-delimited
// HEC event objects (Splunk's preferred batch format — fewer round
// trips than one event per POST, no need for a wrapping array).
type SplunkEmitter struct {
	cfg  SplunkConfig
	be   *batchEmitter
	name string
}

// NewSplunkEmitter validates config, builds the emitter, and starts
// its worker. Returns an error rather than a half-configured emitter
// so the gateway fails fast on misconfig.
func NewSplunkEmitter(cfg SplunkConfig) (*SplunkEmitter, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("siem/splunk: URL is required")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("siem/splunk: Token is required")
	}
	if cfg.Source == "" {
		cfg.Source = "intentgate"
	}
	if cfg.Sourcetype == "" {
		cfg.Sourcetype = "_json"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	se := &SplunkEmitter{cfg: cfg, name: "splunk"}
	se.be = newBatchEmitter(batchConfig{
		Name:   se.name,
		Flush:  httpFlusher(cfg.HTTPClient, se.buildRequest),
		Logger: cfg.Logger,
	})
	return se, nil
}

// Emit forwards the event to the batched worker.
func (s *SplunkEmitter) Emit(ctx context.Context, ev audit.Event) {
	s.be.Emit(ctx, ev)
}

// Stop drains the worker.
func (s *SplunkEmitter) Stop(ctx context.Context) error { return s.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The endpoint
// URL is exposed; the token never is.
func (s *SplunkEmitter) Status() Status {
	return s.be.counters.snapshot(s.name, s.cfg.URL, true)
}

// hecEvent is the Splunk HEC envelope. Time is unix epoch (float
// seconds) because that's what HEC expects; everything else is
// metadata.
type hecEvent struct {
	Time       float64     `json:"time"`
	Host       string      `json:"host,omitempty"`
	Source     string      `json:"source,omitempty"`
	Sourcetype string      `json:"sourcetype,omitempty"`
	Index      string      `json:"index,omitempty"`
	Event      audit.Event `json:"event"`
}

func (s *SplunkEmitter) buildRequest(events []audit.Event) (*http.Request, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		t := parseEventTime(ev.Timestamp)
		envelope := hecEvent{
			Time:       float64(t.UnixNano()) / 1e9,
			Source:     s.cfg.Source,
			Sourcetype: s.cfg.Sourcetype,
			Index:      s.cfg.Index,
			Event:      ev,
		}
		if err := enc.Encode(envelope); err != nil {
			return nil, fmt.Errorf("siem/splunk: encode: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, s.cfg.URL, &buf)
	if err != nil {
		return nil, fmt.Errorf("siem/splunk: new request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// parseEventTime tolerates the few timestamp formats audit.Event
// might carry (RFC3339Nano normally, RFC3339 belt-and-braces). Falls
// back to "now" so a malformed timestamp doesn't lose the event.
func parseEventTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
