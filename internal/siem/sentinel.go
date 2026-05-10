package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// SentinelConfig configures a Microsoft Sentinel (Azure Monitor Logs)
// emitter against the modern Logs Ingestion API.
//
// Sentinel ingestion requires a four-piece tuple beyond the API
// credentials:
//
//   - DCEUrl       — Data Collection Endpoint, e.g.
//     "https://intentgate-dce-abc1.eastus-1.ingest.monitor.azure.com"
//   - DCRImmutableID — the immutable ID of the Data Collection Rule
//     that routes the stream into the Log Analytics
//     workspace, e.g. "dcr-abcdef1234567890"
//   - StreamName   — the custom-table stream the DCR exposes, e.g.
//     "Custom-IntentGate_CL"
//   - TenantID / ClientID / ClientSecret — Azure AD service-principal
//     credentials with the "Monitoring Metrics
//     Publisher" role on the DCR.
//
// All six are required; missing any causes [NewSentinelEmitter] to
// return an error.
type SentinelConfig struct {
	DCEUrl         string
	DCRImmutableID string
	StreamName     string
	TenantID       string
	ClientID       string
	ClientSecret   string

	// AuthEndpoint overrides the Azure AD token endpoint. Tests use
	// this to point at httptest.Server; production should leave it
	// empty so we use https://login.microsoftonline.com.
	AuthEndpoint string

	// HTTPClient is shared between the auth round-trip and the
	// ingest round-trip. Tests inject a stubbed client; nil falls
	// back to a 30-second-timeout default.
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// SentinelEmitter ships audit events to Microsoft Sentinel via the
// Azure Monitor Logs Ingestion API.
type SentinelEmitter struct {
	cfg    SentinelConfig
	be     *batchEmitter
	name   string
	ingest string
	tokens *tokenCache
}

// NewSentinelEmitter validates the config, constructs the emitter, and
// starts the worker. The token endpoint is NOT contacted at startup;
// the first successful flush triggers the first OAuth round-trip.
// That keeps `helm install` snappy and pushes auth failures into the
// audit log rather than blocking pod startup.
func NewSentinelEmitter(cfg SentinelConfig) (*SentinelEmitter, error) {
	if strings.TrimSpace(cfg.DCEUrl) == "" {
		return nil, errors.New("siem/sentinel: DCEUrl is required")
	}
	if strings.TrimSpace(cfg.DCRImmutableID) == "" {
		return nil, errors.New("siem/sentinel: DCRImmutableID is required")
	}
	if strings.TrimSpace(cfg.StreamName) == "" {
		return nil, errors.New("siem/sentinel: StreamName is required")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("siem/sentinel: TenantID is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("siem/sentinel: ClientID is required")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("siem/sentinel: ClientSecret is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.AuthEndpoint == "" {
		cfg.AuthEndpoint = "https://login.microsoftonline.com"
	}

	ingest := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01",
		strings.TrimRight(cfg.DCEUrl, "/"),
		url.PathEscape(cfg.DCRImmutableID),
		url.PathEscape(cfg.StreamName),
	)

	se := &SentinelEmitter{
		cfg:    cfg,
		name:   "sentinel",
		ingest: ingest,
		tokens: newTokenCache(cfg),
	}
	se.be = newBatchEmitter(batchConfig{
		Name:   se.name,
		Flush:  se.flush,
		Logger: cfg.Logger,
	})
	return se, nil
}

// Emit hands the event to the worker.
func (s *SentinelEmitter) Emit(ctx context.Context, ev audit.Event) {
	s.be.Emit(ctx, ev)
}

// Stop drains the worker.
func (s *SentinelEmitter) Stop(ctx context.Context) error { return s.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The DCE URL
// is exposed (not secret); credentials never are.
func (s *SentinelEmitter) Status() Status {
	return s.be.counters.snapshot(s.name, s.cfg.DCEUrl, true)
}

// flush is the per-batch worker callback. Acquires a fresh token if
// the cached one is missing or near-expired, then POSTs the events
// JSON-encoded as an array.
func (s *SentinelEmitter) flush(ctx context.Context, events []audit.Event) error {
	token, err := s.tokens.get(ctx, s.cfg.HTTPClient)
	if err != nil {
		return fmt.Errorf("siem/sentinel: auth: %w", err)
	}

	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("siem/sentinel: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ingest, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siem/sentinel: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Force a token refresh on the next flush in case the cached
		// token rotated under us mid-window.
		s.tokens.invalidate()
		return &permanentHTTPError{status: resp.StatusCode}
	}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &transientHTTPError{status: resp.StatusCode}
	}
	if resp.StatusCode >= 400 {
		return &permanentHTTPError{status: resp.StatusCode}
	}
	return nil
}

// tokenCache holds the most recent Azure AD access token for the
// configured service principal, refreshing automatically near expiry.
//
// Refresh-window is 5 minutes: we treat a token as expired once it's
// within 5 minutes of its real expiry to avoid a request crossing the
// boundary mid-flight.
type tokenCache struct {
	cfg SentinelConfig

	mu     sync.Mutex
	access string
	exp    time.Time
}

func newTokenCache(cfg SentinelConfig) *tokenCache {
	return &tokenCache{cfg: cfg}
}

const refreshWindow = 5 * time.Minute

// get returns a fresh access token, requesting a new one if the
// cached one is missing or near expiry. Concurrency-safe; concurrent
// callers during a refresh serialise on the mutex.
func (t *tokenCache) get(ctx context.Context, client *http.Client) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.access != "" && time.Until(t.exp) > refreshWindow {
		return t.access, nil
	}

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token",
		strings.TrimRight(t.cfg.AuthEndpoint, "/"),
		url.PathEscape(t.cfg.TenantID))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.cfg.ClientID)
	form.Set("client_secret", t.cfg.ClientSecret)
	form.Set("scope", "https://monitor.azure.com//.default")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("siem/sentinel: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return "", fmt.Errorf("siem/sentinel: token endpoint returned %d: %s",
			resp.StatusCode, string(body))
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("siem/sentinel: decode token: %w", err)
	}
	if body.AccessToken == "" {
		return "", errors.New("siem/sentinel: token endpoint returned empty access_token")
	}

	t.access = body.AccessToken
	if body.ExpiresIn <= 0 {
		// Defensive: Azure normally returns 3599; if missing assume
		// one hour so we still cache.
		body.ExpiresIn = 3600
	}
	t.exp = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	return t.access, nil
}

// invalidate forces the next get() to round-trip Azure AD even if the
// cached token's clock-time hasn't expired. Used after a 401/403 from
// the ingest endpoint, which usually means the principal's
// permissions changed mid-window.
func (t *tokenCache) invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.access = ""
	t.exp = time.Time{}
}
