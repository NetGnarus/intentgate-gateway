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

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
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
type AdminConfig struct {
	Logger     *slog.Logger
	AdminToken string
	Revocation revocation.Store
	Audit      audit.Emitter
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
