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

// DatadogConfig configures a Datadog Logs Intake emitter.
type DatadogConfig struct {
	// APIKey is the Datadog API key, sent as the "DD-API-KEY" header.
	// Required.
	APIKey string
	// Site selects the regional Datadog endpoint:
	//   "datadoghq.com"     (US1, default)
	//   "datadoghq.eu"      (EU)
	//   "us3.datadoghq.com" (US3)
	//   "us5.datadoghq.com" (US5)
	//   "ap1.datadoghq.com" (AP1)
	// Custom values are accepted verbatim — host becomes
	// "https://http-intake.logs.<Site>".
	Site string
	// Service tags every event's "service" field. Defaults to
	// "intentgate-gateway".
	Service string
	// Source / Hostname / Tags are pass-through Datadog metadata.
	// Source defaults to "intentgate", Hostname to "" (Datadog fills
	// from the agent / network), Tags to nil.
	Source   string
	Hostname string
	Tags     []string
	// HTTPClient is injected in tests; nil falls back to a default
	// client with a 30-second total timeout.
	HTTPClient *http.Client
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// DatadogEmitter ships audit events to Datadog Logs Intake.
type DatadogEmitter struct {
	cfg  DatadogConfig
	be   *batchEmitter
	url  string
	name string
}

// NewDatadogEmitter validates config and starts the worker.
func NewDatadogEmitter(cfg DatadogConfig) (*DatadogEmitter, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("siem/datadog: APIKey is required")
	}
	if cfg.Site == "" {
		cfg.Site = "datadoghq.com"
	}
	if cfg.Service == "" {
		cfg.Service = "intentgate-gateway"
	}
	if cfg.Source == "" {
		cfg.Source = "intentgate"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	url := "https://http-intake.logs." + cfg.Site + "/api/v2/logs"

	de := &DatadogEmitter{cfg: cfg, url: url, name: "datadog"}
	de.be = newBatchEmitter(batchConfig{
		Name:   de.name,
		Flush:  httpFlusher(cfg.HTTPClient, de.buildRequest),
		Logger: cfg.Logger,
	})
	return de, nil
}

// Emit hands the event to the batched worker.
func (d *DatadogEmitter) Emit(ctx context.Context, ev audit.Event) {
	d.be.Emit(ctx, ev)
}

// Stop drains the worker.
func (d *DatadogEmitter) Stop(ctx context.Context) error { return d.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. URL is
// exposed; the API key never is.
func (d *DatadogEmitter) Status() Status {
	return d.be.counters.snapshot(d.name, d.url, true)
}

// ddLog is the wire shape Datadog Logs Intake accepts. The "ddtags"
// string is comma-separated; every other field is plain JSON. The
// audit event itself is nested under "audit" so Datadog facets it
// without conflicting with reserved keys (status / message / etc.).
type ddLog struct {
	Service  string `json:"service"`
	Source   string `json:"ddsource"`
	Tags     string `json:"ddtags,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// Datadog's reserved keys. We populate "message" with a short
	// human-readable line so the default UI shows something useful;
	// "status" maps the gateway's allow/block to Datadog severity.
	Message string `json:"message"`
	Status  string `json:"status,omitempty"`
	// Audit holds the verbatim event. Datadog auto-faces nested keys
	// so filters like "@audit.tool:read_invoice" work out of the box.
	Audit audit.Event `json:"audit"`
}

func (d *DatadogEmitter) buildRequest(events []audit.Event) (*http.Request, error) {
	logs := make([]ddLog, 0, len(events))
	for _, ev := range events {
		logs = append(logs, ddLog{
			Service:  d.cfg.Service,
			Source:   d.cfg.Source,
			Tags:     strings.Join(d.cfg.Tags, ","),
			Hostname: d.cfg.Hostname,
			Message:  formatDDMessage(ev),
			Status:   ddStatus(ev),
			Audit:    ev,
		})
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(logs); err != nil {
		return nil, fmt.Errorf("siem/datadog: encode: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, d.url, &buf)
	if err != nil {
		return nil, fmt.Errorf("siem/datadog: new request: %w", err)
	}
	req.Header.Set("DD-API-KEY", d.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// formatDDMessage builds a one-line summary for Datadog's "message"
// column so analysts see the gist at a glance.
func formatDDMessage(ev audit.Event) string {
	agent := ev.AgentID
	if agent == "" {
		agent = "(unknown)"
	}
	return fmt.Sprintf("%s %s tool=%s agent=%s reason=%s",
		ev.Decision, ev.Check, ev.Tool, agent, ev.Reason)
}

// ddStatus maps the gateway's audit decision into a Datadog severity
// level so the default log explorer colors blocks differently from
// allows.
func ddStatus(ev audit.Event) string {
	if ev.Decision == audit.DecisionBlock {
		return "warn"
	}
	return "info"
}
