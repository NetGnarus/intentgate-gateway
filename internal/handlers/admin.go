package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
	"github.com/NetGnarus/intentgate-gateway/internal/capability"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
	"github.com/NetGnarus/intentgate-gateway/internal/siem"
)

// AdminConfig configures the admin-API handlers.
//
// Admin endpoints are guarded by a static shared secret (the admin
// token). The token is supplied at startup via INTENTGATE_ADMIN_TOKEN
// and compared in constant time on every request.
//
// A static token is intentional for v1: it matches the self-hosted,
// single-operator deployment shape the gateway targets and avoids
// dragging in OIDC/JWT machinery before a real second user exists. A
// future commercial control plane can layer a richer auth model in
// front of this same surface.
//
// MasterKey is the HMAC secret used by the mint endpoint. It is the
// same key the gateway uses to verify capability tokens on /v1/mcp;
// the mint endpoint signs new tokens under it. When MasterKey is empty
// the mint endpoint is unavailable (returns 503).
type AdminConfig struct {
	Logger     *slog.Logger
	AdminToken string
	MasterKey  []byte
	Revocation revocation.Store
	Audit      audit.Emitter
	// AuditStore is the queryable audit store consulted by the
	// /v1/admin/audit endpoint. Optional; when nil, that endpoint is
	// not registered.
	AuditStore auditstore.Store
	// SIEMReporters surfaces the configured SIEM-emitter statuses on
	// /v1/admin/integrations. Nil / empty slice yields an empty
	// integrations list rather than a 404 — the console renders that
	// as "no integrations configured" guidance.
	SIEMReporters []siem.StatusReporter
}

// NewAdminRevokeHandler returns the POST /v1/admin/revoke handler.
//
// Body: {"jti": "<token-id>", "reason": "<optional context>"}.
//
// On success returns 200 with {"ok": true}; on validation error 400;
// on missing/invalid admin token 401; on store failure 503.
//
// Idempotent: revoking an already-revoked JTI is not an error.
func NewAdminRevokeHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !checkAdminToken(r, cfg.AdminToken) {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Revocation == nil {
			adminError(w, http.StatusServiceUnavailable, "revocation store not configured")
			return
		}

		var body struct {
			JTI    string `json:"jti"`
			Reason string `json:"reason"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.JTI) == "" {
			adminError(w, http.StatusBadRequest, "jti is required")
			return
		}

		if err := cfg.Revocation.Revoke(r.Context(), body.JTI, body.Reason); err != nil {
			cfg.Logger.Error("revoke failed", "jti", body.JTI, "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		// Audit the revocation action so SOC has a record of WHO told
		// the gateway to drop a token (the operator running igctl, or
		// the admin UI, in either case acting under the admin secret).
		ev := audit.NewEvent(audit.DecisionBlock, "admin/revoke")
		ev.Check = audit.CheckCapability
		ev.Reason = "token revoked: " + body.Reason
		ev.CapabilityTokenID = body.JTI
		ev.RemoteIP = r.RemoteAddr
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("token revoked", "jti", body.JTI, "reason", body.Reason)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "jti": body.JTI})
	})
}

// NewAdminRevocationsListHandler returns the GET /v1/admin/revocations
// handler. Query params: limit (default 100, max 1000), offset
// (default 0). Body: {"revocations": [...]}.
func NewAdminRevocationsListHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !checkAdminToken(r, cfg.AdminToken) {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Revocation == nil {
			adminError(w, http.StatusServiceUnavailable, "revocation store not configured")
			return
		}

		limit := parseIntParam(r, "limit", 100, 1, 1000)
		offset := parseIntParam(r, "offset", 0, 0, 1<<31-1)

		list, err := cfg.Revocation.List(r.Context(), limit, offset)
		if err != nil {
			cfg.Logger.Error("revocation list failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"revocations": list,
			"limit":       limit,
			"offset":      offset,
		})
	})
}

// NewAdminMintHandler returns the POST /v1/admin/mint handler.
//
// Body:
//
//	{
//	  "subject":     "<agent-id>",        // required
//	  "issuer":      "<optional issuer>", // default "intentgate"
//	  "ttl_seconds": 3600,                // optional; 0 = no expiry
//	  "tools":       ["read_invoice"],    // optional whitelist
//	  "max_calls":   100                  // optional budget cap
//	}
//
// On success returns 200 with {"token": "<base64url>", "jti": "<jti>",
// "expires_at": "<RFC3339 or empty>"}.
//
// Returns 400 on validation error, 401 on missing/invalid admin token,
// 503 when the master key isn't configured.
//
// This is the operator-facing path for handing a fresh capability to a
// new agent. It is intentionally a thin wrapper over capability.Mint:
// every restriction (subject lock, expiry, tool whitelist, max-call
// budget) is encoded as a signed caveat, so the resulting token cannot
// be widened by anyone — including the agent that received it.
func NewAdminMintHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !checkAdminToken(r, cfg.AdminToken) {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if len(cfg.MasterKey) == 0 {
			adminError(w, http.StatusServiceUnavailable, "master key not configured: mint disabled")
			return
		}

		var body struct {
			Subject    string   `json:"subject"`
			Issuer     string   `json:"issuer"`
			TTLSeconds int64    `json:"ttl_seconds"`
			Tools      []string `json:"tools"`
			MaxCalls   int      `json:"max_calls"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.Subject) == "" {
			adminError(w, http.StatusBadRequest, "subject is required")
			return
		}
		if body.TTLSeconds < 0 {
			adminError(w, http.StatusBadRequest, "ttl_seconds must be >= 0")
			return
		}
		if body.MaxCalls < 0 {
			adminError(w, http.StatusBadRequest, "max_calls must be >= 0")
			return
		}

		opts := capability.MintOptions{
			Issuer:  strings.TrimSpace(body.Issuer),
			Subject: body.Subject,
		}
		if body.TTLSeconds > 0 {
			opts.Expiry = time.Now().UTC().Add(time.Duration(body.TTLSeconds) * time.Second)
		}
		// De-empty + de-whitespace tools so a stray "" can't widen the
		// effective whitelist on the verifier side.
		var tools []string
		for _, t := range body.Tools {
			t = strings.TrimSpace(t)
			if t != "" {
				tools = append(tools, t)
			}
		}
		if len(tools) > 0 {
			opts.Caveats = append(opts.Caveats, capability.Caveat{
				Type:  capability.CaveatToolWhitelist,
				Tools: tools,
			})
		}
		if body.MaxCalls > 0 {
			opts.Caveats = append(opts.Caveats, capability.Caveat{
				Type:     capability.CaveatMaxCalls,
				MaxCalls: body.MaxCalls,
			})
		}

		tok, err := capability.Mint(cfg.MasterKey, opts)
		if err != nil {
			cfg.Logger.Error("mint failed", "subject", body.Subject, "err", err)
			adminError(w, http.StatusBadRequest, "mint error: "+err.Error())
			return
		}
		encoded, err := tok.Encode()
		if err != nil {
			cfg.Logger.Error("encode failed", "subject", body.Subject, "err", err)
			adminError(w, http.StatusInternalServerError, "encode error")
			return
		}

		// Audit the mint as an Allow event so SOC sees who issued the
		// token, for which subject, and (importantly) the JTI — the
		// only handle they'll have to revoke it later.
		ev := audit.NewEvent(audit.DecisionAllow, "admin/mint")
		ev.Check = audit.CheckCapability
		ev.Reason = "token minted for subject=" + body.Subject
		ev.CapabilityTokenID = tok.ID
		ev.AgentID = body.Subject
		ev.RemoteIP = r.RemoteAddr
		cfg.Audit.Emit(r.Context(), ev)

		var expiresAt string
		if !opts.Expiry.IsZero() {
			expiresAt = opts.Expiry.UTC().Format(time.RFC3339)
		}
		cfg.Logger.Info("token minted", "jti", tok.ID, "subject", body.Subject, "ttl_seconds", body.TTLSeconds, "tools", len(tools), "max_calls", body.MaxCalls)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      encoded,
			"jti":        tok.ID,
			"subject":    body.Subject,
			"expires_at": expiresAt,
		})
	})
}

// NewAdminAuditQueryHandler returns the GET /v1/admin/audit handler.
//
// Query params (all optional):
//
//	from        ISO-8601 timestamp, inclusive lower bound on event ts
//	to          ISO-8601 timestamp, inclusive upper bound
//	agent_id    exact-match filter
//	tool        exact-match filter
//	decision    "allow" or "block"
//	check       "capability" / "intent" / "policy" / "budget" / "upstream"
//	jti         capability_token_id exact-match filter
//	limit       page size, default 100, max 1000
//	offset      pagination offset, default 0
//	count       "true" to additionally return the total count (a
//	            potentially expensive COUNT(*) on large tables)
//
// Body:
//
//	{
//	  "events": [ ... audit.Event records ... ],
//	  "limit":  100,
//	  "offset": 0,
//	  "total":  4321   // only present when count=true
//	}
//
// Returns 401 on missing/invalid admin token, 503 when the audit store
// errors, 400 on unparseable from/to timestamps.
func NewAdminAuditQueryHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !checkAdminToken(r, cfg.AdminToken) {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.AuditStore == nil {
			adminError(w, http.StatusServiceUnavailable, "audit store not configured")
			return
		}

		q := r.URL.Query()
		filter := auditstore.QueryFilter{
			AgentID:           q.Get("agent_id"),
			Tool:              q.Get("tool"),
			Decision:          q.Get("decision"),
			Check:             q.Get("check"),
			CapabilityTokenID: q.Get("jti"),
			Limit:             parseIntParam(r, "limit", 100, 1, 1000),
			Offset:            parseIntParam(r, "offset", 0, 0, 1<<31-1),
		}
		if from := q.Get("from"); from != "" {
			t, err := time.Parse(time.RFC3339, from)
			if err != nil {
				adminError(w, http.StatusBadRequest, "invalid 'from' timestamp: "+err.Error())
				return
			}
			filter.From = t.UTC()
		}
		if to := q.Get("to"); to != "" {
			t, err := time.Parse(time.RFC3339, to)
			if err != nil {
				adminError(w, http.StatusBadRequest, "invalid 'to' timestamp: "+err.Error())
				return
			}
			filter.To = t.UTC()
		}

		events, err := cfg.AuditStore.Query(r.Context(), filter)
		if err != nil {
			cfg.Logger.Error("audit query failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		resp := map[string]any{
			"events": events,
			"limit":  filter.Limit,
			"offset": filter.Offset,
		}
		if q.Get("count") == "true" {
			n, err := cfg.AuditStore.Count(r.Context(), filter)
			if err != nil {
				// Don't fail the whole response; tag the count as
				// unknown so the UI degrades gracefully.
				cfg.Logger.Warn("audit count failed", "err", err)
				resp["total"] = -1
			} else {
				resp["total"] = n
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// NewAdminIntegrationsHandler returns the GET /v1/admin/integrations
// handler. Returns the read-only status of every wired SIEM emitter
// (Splunk, Datadog) plus a stable list of "supported but not
// configured" entries so the console can render greyed-out cards
// with setup hints.
//
// Body:
//
//	{
//	  "integrations": [
//	    {
//	      "name": "splunk",
//	      "configured": true,
//	      "endpoint": "https://splunk.example:8088/services/collector",
//	      "last_flush_ts": "2026-05-09T15:30:00Z",
//	      "total_events": 1234,
//	      "dropped_count": 0,
//	      "last_error": ""
//	    },
//	    { "name": "datadog", "configured": false }
//	  ]
//	}
//
// Sensitive config (tokens, API keys) is never returned.
func NewAdminIntegrationsHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !checkAdminToken(r, cfg.AdminToken) {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}

		// Index by name so we can fill stubs for the integrations the
		// gateway *supports* but the operator hasn't wired up. The
		// console wants a stable card grid; "splunk + datadog" is the
		// canonical order in v0.6.
		statuses := make(map[string]siem.Status)
		for _, rep := range cfg.SIEMReporters {
			s := rep.Status()
			statuses[s.Name] = s
		}

		out := make([]siem.Status, 0, 3)
		for _, name := range []string{"splunk", "datadog", "sentinel"} {
			if s, ok := statuses[name]; ok {
				out = append(out, s)
			} else {
				out = append(out, siem.Status{Name: name, Configured: false})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"integrations": out})
	})
}

// checkAdminToken returns true if the request carries a valid admin
// token. Admin endpoints are unavailable when AdminToken is empty —
// safer than degrading to "anyone can revoke any token", which is the
// nightmare scenario.
func checkAdminToken(r *http.Request, want string) bool {
	if want == "" {
		return false
	}
	got := r.Header.Get("Authorization")
	got = strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// adminError writes a small JSON error body and the given status.
func adminError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// parseIntParam reads a positive integer from a query string with
// sane defaulting and clamping. A non-integer value silently falls
// back to def; the admin API isn't a place to fight clients over
// query-string types.
func parseIntParam(r *http.Request, name string, def, minVal, maxVal int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

// errAdminTokenRequired is returned by helpers that refuse to run
// when no admin token is configured.
var errAdminTokenRequired = errors.New("admin token required") //nolint:unused
