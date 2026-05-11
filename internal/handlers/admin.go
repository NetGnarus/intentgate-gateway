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

	"github.com/NetGnarus/intentgate-gateway/internal/approvals"
	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
	"github.com/NetGnarus/intentgate-gateway/internal/capability"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
	"github.com/NetGnarus/intentgate-gateway/internal/siem"
)

// AdminConfig configures the admin-API handlers.
//
// Admin endpoints are guarded by static shared secrets (the admin
// tokens). Tokens come in two flavours:
//
//   - Superadmin (AdminToken). One token, sees and operates on every
//     tenant. Useful for break-glass and ops. Disabled when empty.
//   - Per-tenant (TenantAdmins). One token per tenant. Each token
//     scopes ALL admin operations to that single tenant: mint stamps
//     it, revoke writes it, list filters it, audit query forces the
//     filter, approvals decide rejects cross-tenant ids as 404.
//
// Both shapes can coexist. Tokens are compared in constant time on
// every request — across the entire registry, so a per-tenant
// attempt doesn't reveal which tenant's token they tried.
//
// A static token is intentional for v1: it matches the self-hosted,
// single-operator deployment shape the gateway targets and avoids
// dragging in OIDC/JWT machinery before a real second user exists.
//
// MasterKey is the HMAC secret used by the mint endpoint. When
// MasterKey is empty the mint endpoint is unavailable (returns 503).
type AdminConfig struct {
	Logger     *slog.Logger
	AdminToken string
	// TenantAdmins maps tenant name → token. Empty / nil means no
	// per-tenant admins are configured; only the superadmin (if set)
	// can hit /v1/admin/*.
	TenantAdmins map[string]string
	MasterKey    []byte
	Revocation   revocation.Store
	Audit        audit.Emitter
	// AuditStore is the queryable audit store consulted by the
	// /v1/admin/audit endpoint. Optional; when nil, that endpoint is
	// not registered.
	AuditStore auditstore.Store
	// SIEMReporters surfaces the configured SIEM-emitter statuses on
	// /v1/admin/integrations. Nil / empty slice yields an empty
	// integrations list rather than a 404 — the console renders that
	// as "no integrations configured" guidance.
	SIEMReporters []siem.StatusReporter
	// Approvals is the queue the /v1/admin/approvals endpoints read
	// from. nil disables those routes (they're not registered).
	Approvals approvals.Store
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

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
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

		if err := cfg.Revocation.Revoke(r.Context(), body.JTI, body.Reason, auth.tenant); err != nil {
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
		ev.Tenant = auth.tenant
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

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Revocation == nil {
			adminError(w, http.StatusServiceUnavailable, "revocation store not configured")
			return
		}

		limit := parseIntParam(r, "limit", 100, 1, 1000)
		offset := parseIntParam(r, "offset", 0, 0, 1<<31-1)

		list, err := cfg.Revocation.List(r.Context(), auth.tenant, limit, offset)
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
//	  "max_calls":   100,                 // optional budget cap
//	  "step_up":     true                 // optional step-up annotation
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
//
// # Step-up annotation
//
// When step_up is true the minted token carries a signed
// [capability.CaveatStepUp] caveat with the current unix-seconds
// timestamp. Rego policies gating high-risk operations read
// `input.capability.step_up_at` to require recent fresh-factor
// presence (e.g. `now - step_up_at < 300`). The gateway does NOT
// verify a fresh factor here — that's the caller's responsibility:
// the Pro console performs TOTP / WebAuthn verification and calls
// this endpoint with step_up:true to mint an elevated token. The
// admin-token authentication is the trust boundary; whoever holds it
// can mint step-up tokens, so operators MUST rotate the admin token
// out of band when an operator leaves.
func NewAdminMintHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
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
			Tenant     string   `json:"tenant"`
			TTLSeconds int64    `json:"ttl_seconds"`
			Tools      []string `json:"tools"`
			MaxCalls   int      `json:"max_calls"`
			StepUp     bool     `json:"step_up"`
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

		// Tenant resolution rules:
		//   - Per-tenant admin: their tenant wins. Body field is
		//     ignored (or rejected if it disagrees) so a stolen
		//     token can't be used to mint cross-tenant.
		//   - Superadmin: body.tenant is honored, defaulting to
		//     "default" via Mint when empty.
		tenant := strings.TrimSpace(body.Tenant)
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in body does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		opts := capability.MintOptions{
			Issuer:  strings.TrimSpace(body.Issuer),
			Tenant:  tenant,
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
		if body.StepUp {
			// Stamp the current unix-seconds timestamp into the
			// signed caveat. Rego policies read this via
			// input.capability.step_up_at and decide what "fresh
			// enough" means for the operation at hand.
			opts.Caveats = append(opts.Caveats, capability.Caveat{
				Type:     capability.CaveatStepUp,
				StepUpAt: time.Now().UTC().Unix(),
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
		ev.RootCapabilityTokenID = tok.RootID
		ev.CaveatCount = tok.CaveatCount()
		ev.Tenant = tok.Tenant
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

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.AuditStore == nil {
			adminError(w, http.StatusServiceUnavailable, "audit store not configured")
			return
		}

		q := r.URL.Query()
		// Per-tenant admins: tenant is forced from the resolver,
		// query-string tenant is ignored (and rejected if it
		// disagrees, to avoid a confusing silent override).
		// Superadmin: ?tenant= is honored verbatim.
		tenant := q.Get("tenant")
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		filter := auditstore.QueryFilter{
			AgentID:           q.Get("agent_id"),
			Tool:              q.Get("tool"),
			Decision:          q.Get("decision"),
			Check:             q.Get("check"),
			CapabilityTokenID: q.Get("jti"),
			Tenant:            tenant,
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

// NewAdminAuditVerifyHandler returns the GET /v1/admin/audit/verify
// handler (Pro v2 #4, session 54).
//
// Query params:
//
//	tenant      tenant whose chain to verify. Defaults to the admin
//	            token's bound tenant; superadmin may pass any value
//	            (empty = "default" — see auditstore.VerifyChain).
//	from / to   optional RFC3339 timestamps narrowing the window.
//
// Body:
//
//	{
//	  "ok":       true,
//	  "tenant":   "acme",
//	  "verified": 12345,
//	  "skipped":  0,
//	  "broken_at": null      // or { id, ts, stored_hash, expected_hash, reason }
//	}
//
// 200 on every successful walk regardless of OK/!OK — the body
// carries the verdict. 401 on bad auth, 503 when the audit store
// isn't configured, 400 on bad timestamps.
//
// Sensitive data (event reasons, agent ids) is NOT included in the
// response. Operators wanting the offending row's full body query
// /v1/admin/audit with the returned id.
func NewAdminAuditVerifyHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.AuditStore == nil {
			adminError(w, http.StatusServiceUnavailable, "audit store not configured")
			return
		}

		q := r.URL.Query()
		// Per-tenant admin: tenant forced from the resolved auth, body
		// param ignored (or rejected on disagreement). Superadmin: ?tenant=
		// honored verbatim.
		tenant := strings.TrimSpace(q.Get("tenant"))
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		filter := auditstore.VerifyFilter{Tenant: tenant}
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

		result, err := cfg.AuditStore.VerifyChain(r.Context(), filter)
		if err != nil {
			cfg.Logger.Error("audit verify failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "verify error: "+err.Error())
			return
		}

		resp := map[string]any{
			"ok":       result.OK,
			"tenant":   tenant,
			"verified": result.Verified,
			"skipped":  result.Skipped,
		}
		if result.BrokenAt != nil {
			resp["broken_at"] = map[string]any{
				"id":            result.BrokenAt.ID,
				"ts":            result.BrokenAt.Timestamp.UTC().Format(time.RFC3339Nano),
				"stored_hash":   result.BrokenAt.StoredHash,
				"expected_hash": result.BrokenAt.ExpectedHash,
				"reason":        result.BrokenAt.Reason,
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

// NewAdminApprovalsListHandler returns the GET /v1/admin/approvals
// handler. Surfaces the queue of pending (or decided) approvals to
// the operator console.
//
// Query params:
//
//	status  pending | approved | rejected | timeout (default: empty = all)
//	limit   page size (default 100, max 1000)
//	offset  pagination offset
//
// Body: {"approvals": [...PendingRequest], "limit": N, "offset": N}.
func NewAdminApprovalsListHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Approvals == nil {
			adminError(w, http.StatusServiceUnavailable, "approvals queue not configured")
			return
		}

		filter := approvals.ListFilter{
			Status: approvals.Status(r.URL.Query().Get("status")),
			Tenant: auth.tenant,
			Limit:  parseIntParam(r, "limit", 100, 1, 1000),
			Offset: parseIntParam(r, "offset", 0, 0, 1<<31-1),
		}
		rows, err := cfg.Approvals.List(r.Context(), filter)
		if err != nil {
			cfg.Logger.Error("approvals list failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"approvals": rows,
			"limit":     filter.Limit,
			"offset":    filter.Offset,
		})
	})
}

// NewAdminApprovalsDecideHandler returns the
// POST /v1/admin/approvals/{id}/decide handler.
//
// Body: {"decision": "approve"|"reject", "decided_by": "name", "note": ""}.
//
// 200 on success with the updated row. 401 invalid token, 404
// unknown id, 409 already decided, 400 malformed body.
func NewAdminApprovalsDecideHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Approvals == nil {
			adminError(w, http.StatusServiceUnavailable, "approvals queue not configured")
			return
		}

		pendingID := r.PathValue("id")
		if pendingID == "" {
			adminError(w, http.StatusBadRequest, "missing pending id")
			return
		}

		var body struct {
			Decision  string `json:"decision"`
			DecidedBy string `json:"decided_by"`
			Note      string `json:"note"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		var status approvals.Status
		switch body.Decision {
		case "approve":
			status = approvals.StatusApproved
		case "reject":
			status = approvals.StatusRejected
		default:
			adminError(w, http.StatusBadRequest, `decision must be "approve" or "reject"`)
			return
		}

		// Tenant scoping: a per-tenant admin can only decide rows in
		// their tenant. We pre-check via Get so cross-tenant attempts
		// return 404 (don't leak existence) rather than 403.
		if auth.tenant != "" {
			existing, gerr := cfg.Approvals.Get(r.Context(), pendingID)
			if errors.Is(gerr, approvals.ErrNotFound) || existing.Tenant != auth.tenant {
				adminError(w, http.StatusNotFound, "pending id not found")
				return
			}
			if gerr != nil {
				cfg.Logger.Error("approvals get failed", "err", gerr, "pending_id", pendingID)
				adminError(w, http.StatusServiceUnavailable, "store error: "+gerr.Error())
				return
			}
		}

		row, err := cfg.Approvals.Decide(r.Context(), pendingID, approvals.Decision{
			Status:    status,
			DecidedBy: body.DecidedBy,
			Note:      body.Note,
		})
		if errors.Is(err, approvals.ErrNotFound) {
			adminError(w, http.StatusNotFound, "pending id not found")
			return
		}
		if errors.Is(err, approvals.ErrAlreadyDecided) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "already decided",
				"current": row,
			})
			return
		}
		if err != nil {
			cfg.Logger.Error("approval decide failed", "err", err, "pending_id", pendingID)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(row)
	})
}

// NewAdminTenantsListHandler returns the GET /v1/admin/tenants handler.
//
// Surfaces the configured tenant identifiers so the console can
// populate a tenant switcher. Scoping rules mirror the rest of the
// admin API:
//
//   - Superadmin sees every tenant in cfg.TenantAdmins, sorted.
//   - A per-tenant admin sees only their own tenant.
//   - When the gateway is configured with neither (a single-tenant
//     deploy that never set TenantAdmins) the response is an empty
//     list — the console renders that as "no tenants configured" and
//     hides the switcher rather than 404'ing.
//
// Body: {"tenants": [{"id": "acme", "has_admin": true}, ...]}.
// has_admin is reserved for a future "tenants without an admin token
// configured" view; today it is always true because every entry in
// the response originates from cfg.TenantAdmins.
func NewAdminTenantsListHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}

		type tenantEntry struct {
			ID       string `json:"id"`
			HasAdmin bool   `json:"has_admin"`
		}

		var out []tenantEntry
		if auth.tenant != "" {
			// Per-tenant admin sees only its own tenant. We don't even
			// look at cfg.TenantAdmins here — the resolved tenant came
			// from constant-time auth, so it's already authoritative.
			out = []tenantEntry{{ID: auth.tenant, HasAdmin: true}}
		} else {
			// Superadmin: every configured tenant, sorted for stable
			// rendering in the switcher. We don't include the empty
			// "" tenant; that's the superadmin scope itself, which the
			// UI represents implicitly with "All tenants".
			ids := make([]string, 0, len(cfg.TenantAdmins))
			for tenant, tok := range cfg.TenantAdmins {
				if tenant == "" || tok == "" {
					continue
				}
				ids = append(ids, tenant)
			}
			// Sort in-place. sort.Strings is alphabetic which is good
			// enough for a switcher (single-screen list, no pagination).
			sortStringsInPlace(ids)
			out = make([]tenantEntry, 0, len(ids))
			for _, id := range ids {
				out = append(out, tenantEntry{ID: id, HasAdmin: true})
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"tenants": out})
	})
}

// sortStringsInPlace is a tiny helper to keep the main package free
// of an extra "sort" import here. Insertion sort is fine: tenant
// counts are O(10) in practice; even O(1000) would still be cheap on
// every admin request, and avoiding sort.Strings keeps imports tight.
func sortStringsInPlace(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// adminAuth is the result of resolving a request's bearer token
// against AdminConfig. ok=false means deny. ok=true with tenant=""
// means superadmin (sees all tenants). ok=true with non-empty tenant
// means a per-tenant admin scoped to that tenant.
type adminAuth struct {
	ok     bool
	tenant string
}

// resolveAdminAuth checks the request's bearer token against the
// superadmin token first, then every per-tenant token. ALL slots are
// compared even on a hit — constant-time across the whole registry
// so the response time doesn't leak which slot matched (or whether
// any did). Empty config slots are skipped before the loop, not
// during, so the per-request work is bounded by configured tenants.
func resolveAdminAuth(r *http.Request, cfg AdminConfig) adminAuth {
	got := r.Header.Get("Authorization")
	got = strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	if got == "" {
		return adminAuth{}
	}
	gotBytes := []byte(got)

	out := adminAuth{}
	// Superadmin first. ConstantTimeCompare with mismatched lengths
	// returns 0 immediately; we still walk the per-tenant slots
	// regardless to keep timing flat.
	if cfg.AdminToken != "" &&
		subtle.ConstantTimeCompare(gotBytes, []byte(cfg.AdminToken)) == 1 {
		out = adminAuth{ok: true, tenant: ""}
	}
	for tenant, want := range cfg.TenantAdmins {
		if want == "" {
			continue
		}
		if subtle.ConstantTimeCompare(gotBytes, []byte(want)) == 1 && !out.ok {
			out = adminAuth{ok: true, tenant: tenant}
		}
	}
	return out
}

// checkAdminToken is the legacy boolean shim retained for
// compatibility with handlers that haven't been ported to
// resolveAdminAuth yet. Treats empty tenant ("superadmin") and any
// per-tenant match the same. New handlers should call
// resolveAdminAuth directly so they can scope by the resolved tenant.
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

// dryRunMaxEvents is the upper bound on how many audit events a single
// dry-run will pull from the store. 100k is enough for "last 24 hours"
// on a busy customer install while keeping worst-case memory and
// evaluation latency bounded (~tens of MB / a few seconds).
const dryRunMaxEvents = 100000

// dryRunDefaultEvents is the cap applied when the caller doesn't ask
// for a specific limit. Keeps interactive UI calls snappy.
const dryRunDefaultEvents = 10000

// NewAdminPoliciesDryRunHandler returns the POST /v1/admin/policies/dry-run
// handler.
//
// Request body:
//
//	{
//	  "rego":     "package intentgate.policy\nimport rego.v1\n...",  // required
//	  "from":     "2026-05-09T00:00:00Z",  // optional, RFC3339
//	  "to":       "2026-05-10T00:00:00Z",  // optional, RFC3339
//	  "limit":    10000,                   // optional, default 10000, max 100000
//	  "agent_id": "fin-bot",               // optional filter
//	  "tool":     "transfer_funds",        // optional filter
//	  "max_samples": 100                   // optional, default 100
//	}
//
// The endpoint pulls events from the audit store, replays the
// candidate Rego policy against each one, and returns the cross-tab
// of original × candidate decisions plus a sample of divergent rows.
// Tenant scoping mirrors /v1/admin/audit: superadmin can pass
// `tenant` in the body to scope; per-tenant admin is forced to their
// own tenant.
//
// Returns 400 on missing/invalid body or compile error, 401 on bad
// token, 503 when the audit store isn't configured.
func NewAdminPoliciesDryRunHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.AuditStore == nil {
			adminError(w, http.StatusServiceUnavailable,
				"audit store not configured; dry-run requires INTENTGATE_AUDIT_PERSIST=true on the gateway")
			return
		}

		var body struct {
			Rego       string `json:"rego"`
			From       string `json:"from,omitempty"`
			To         string `json:"to,omitempty"`
			Limit      int    `json:"limit,omitempty"`
			AgentID    string `json:"agent_id,omitempty"`
			Tool       string `json:"tool,omitempty"`
			MaxSamples int    `json:"max_samples,omitempty"`
			Tenant     string `json:"tenant,omitempty"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap on body
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		if strings.TrimSpace(body.Rego) == "" {
			adminError(w, http.StatusBadRequest, "missing required field \"rego\"")
			return
		}

		// Tenant scoping: per-tenant admin's token forces the filter;
		// superadmin honors the body's tenant verbatim.
		tenant := body.Tenant
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in body does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		// Clamp inputs.
		limit := body.Limit
		if limit <= 0 {
			limit = dryRunDefaultEvents
		}
		if limit > dryRunMaxEvents {
			limit = dryRunMaxEvents
		}
		maxSamples := body.MaxSamples
		if maxSamples <= 0 {
			maxSamples = policy.DefaultMaxSamples
		}
		if maxSamples > 1000 {
			maxSamples = 1000
		}

		// Walk the audit store in pages of 1000 (the store-level cap)
		// until we either reach the operator-specified limit or run out
		// of events.
		const pageSize = 1000
		filter := auditstore.QueryFilter{
			AgentID: body.AgentID,
			Tool:    body.Tool,
			Tenant:  tenant,
			Limit:   pageSize,
		}
		if body.From != "" {
			t, err := time.Parse(time.RFC3339, body.From)
			if err != nil {
				adminError(w, http.StatusBadRequest, "invalid 'from' timestamp: "+err.Error())
				return
			}
			filter.From = t.UTC()
		}
		if body.To != "" {
			t, err := time.Parse(time.RFC3339, body.To)
			if err != nil {
				adminError(w, http.StatusBadRequest, "invalid 'to' timestamp: "+err.Error())
				return
			}
			filter.To = t.UTC()
		}

		events := make([]audit.Event, 0, limit)
		offset := 0
		for len(events) < limit {
			filter.Offset = offset
			remaining := limit - len(events)
			if remaining < pageSize {
				filter.Limit = remaining
			}
			page, err := cfg.AuditStore.Query(r.Context(), filter)
			if err != nil {
				cfg.Logger.Error("dry-run: audit query failed", "err", err)
				adminError(w, http.StatusServiceUnavailable, "audit store error: "+err.Error())
				return
			}
			if len(page) == 0 {
				break
			}
			events = append(events, page...)
			if len(page) < filter.Limit {
				break
			}
			offset += len(page)
		}

		result, err := policy.DryRun(r.Context(), body.Rego, events, policy.DryRunOptions{
			MaxSamples: maxSamples,
		})
		if err != nil {
			// Distinguish compile errors (operator's policy doesn't
			// parse) from runtime errors. Compile errors are 400 so
			// the UI can surface "your draft policy didn't compile".
			cfg.Logger.Info("dry-run: rejected", "err", err)
			if strings.Contains(err.Error(), "compile candidate") ||
				strings.Contains(err.Error(), "prepare for eval") ||
				strings.Contains(err.Error(), "non-empty Rego source") {
				adminError(w, http.StatusBadRequest, err.Error())
				return
			}
			adminError(w, http.StatusServiceUnavailable, err.Error())
			return
		}

		// Attach the input window to the response so the UI can render
		// "evaluated against N events between X and Y" without round-
		// tripping the request body.
		resp := struct {
			policy.DryRunResult
			Window struct {
				From   string `json:"from,omitempty"`
				To     string `json:"to,omitempty"`
				Tenant string `json:"tenant,omitempty"`
				Limit  int    `json:"limit"`
			} `json:"window"`
		}{DryRunResult: result}
		resp.Window.From = body.From
		resp.Window.To = body.To
		resp.Window.Tenant = tenant
		resp.Window.Limit = limit
		_ = json.NewEncoder(w).Encode(resp)
	})
}
