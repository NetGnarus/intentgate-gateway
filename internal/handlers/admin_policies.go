package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/policystore"
)

// PolicyAdminConfig configures the policy-draft + active-pointer
// admin endpoints. Distinct from AdminConfig to keep the latter
// focused on the original v1.0 surface (revocations, mint, audit,
// approvals, integrations). The handlers share resolveAdminAuth via
// closure capture below.
type PolicyAdminConfig struct {
	Logger *slog.Logger
	// Admin auth: handlers resolve against the same superadmin +
	// per-tenant tokens the rest of the admin API uses.
	AdminToken   string
	TenantAdmins map[string]string

	// Store is the policystore backend (memory / postgres).
	Store policystore.Store

	// Reloader is the live policy holder the gateway's MCP handler
	// reads on every tool call. On promote / rollback we compile the
	// new draft and Swap into the reloader so the next request sees
	// the new module — no gateway restart required. nil disables
	// promote / rollback (returns 503 with a helpful message).
	Reloader *policy.Reloader

	// Audit lets promote / rollback / draft-create emit one event
	// each so SOC has a record of who flipped the gateway's policy.
	Audit audit.Emitter
}

// adminConfig is a tiny shim so the policy admin handlers can call
// resolveAdminAuth without taking a full AdminConfig dependency.
// resolveAdminAuth itself only reads AdminToken and TenantAdmins.
func (cfg PolicyAdminConfig) adminConfig() AdminConfig {
	return AdminConfig{
		AdminToken:   cfg.AdminToken,
		TenantAdmins: cfg.TenantAdmins,
	}
}

// NewAdminDraftsListHandler returns GET /v1/admin/policies/drafts.
//
// Query params:
//
//	limit   page size, default 100, max 1000
//	offset  pagination offset
//	tenant  superadmin-only filter; per-tenant admins are forced to
//	        their own tenant (mismatching ?tenant= returns 403)
//
// Body:
//
//	{"drafts": [...Draft], "limit": 100, "offset": 0}
//
// Returns 401 on bad token, 503 on store error.
func NewAdminDraftsListHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}

		// Per-tenant: forced; ?tenant= disagreement is 403 (matches
		// /v1/admin/audit's behavior).
		tenant := r.URL.Query().Get("tenant")
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		limit := parseIntParam(r, "limit", 100, 1, 1000)
		offset := parseIntParam(r, "offset", 0, 0, 1<<31-1)
		drafts, err := cfg.Store.ListDrafts(r.Context(), policystore.ListFilter{
			Tenant: tenant,
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			cfg.Logger.Error("drafts list failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"drafts": drafts,
			"limit":  limit,
			"offset": offset,
		})
	})
}

// draftBody is the create / update request shape.
type draftBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	RegoSource  string `json:"rego_source"`
	CreatedBy   string `json:"created_by"`
	Tenant      string `json:"tenant"`
}

// compilePolicy compiles the source so we can reject obviously
// broken drafts at save time instead of at promote time. Returns
// an error string suitable for adminError; the operator sees the
// compile message verbatim in the console.
func compilePolicy(ctx context.Context, source string) error {
	_, err := policy.NewEngine(ctx, source)
	return err
}

// NewAdminDraftsCreateHandler returns POST /v1/admin/policies/drafts.
//
// Body:
//
//	{"name": "...", "description": "...", "rego_source": "...",
//	 "created_by": "...", "tenant": "..."}
//
// On success returns 201 with the populated draft (ID + timestamps).
// 400 on Rego compile error or missing source. 403 if the body's
// tenant disagrees with a per-tenant admin's resolved tenant.
func NewAdminDraftsCreateHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}

		var body draftBody
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20)) // 1 MiB
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.RegoSource) == "" {
			adminError(w, http.StatusBadRequest, "rego_source is required")
			return
		}

		// Compile-on-save: known-bad Rego doesn't make it into the
		// store. The error wraps OPA's parser output verbatim, which
		// is what the console editor wants to surface.
		if err := compilePolicy(r.Context(), body.RegoSource); err != nil {
			adminError(w, http.StatusBadRequest, "rego compile error: "+err.Error())
			return
		}

		tenant := strings.TrimSpace(body.Tenant)
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in body does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		created, err := cfg.Store.CreateDraft(r.Context(), policystore.Draft{
			Name:        body.Name,
			Description: body.Description,
			RegoSource:  body.RegoSource,
			Tenant:      tenant,
			CreatedBy:   body.CreatedBy,
		})
		if err != nil {
			cfg.Logger.Error("draft create failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		cfg.Logger.Info("policy draft created",
			"id", created.ID, "tenant", tenant, "created_by", body.CreatedBy)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(created)
	})
}

// NewAdminDraftGetHandler returns GET /v1/admin/policies/drafts/{id}.
//
// Tenant scoping: a per-tenant admin gets 404 (not 403) when
// reading another tenant's draft, matching the approvals-decide
// pattern that doesn't leak cross-tenant existence.
func NewAdminDraftGetHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}

		id := r.PathValue("id")
		if id == "" {
			adminError(w, http.StatusBadRequest, "missing draft id")
			return
		}
		d, err := cfg.Store.GetDraft(r.Context(), id)
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		if err != nil {
			cfg.Logger.Error("draft get failed", "err", err, "id", id)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		// Per-tenant: pretend the row doesn't exist when it's not
		// theirs.
		if auth.tenant != "" && d.Tenant != auth.tenant {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	})
}

// NewAdminDraftUpdateHandler returns PUT /v1/admin/policies/drafts/{id}.
//
// Body shape mirrors create. Tenant on the body is ignored — the
// stored row's tenant is immutable; we only re-check it for
// cross-tenant deny.
func NewAdminDraftUpdateHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}

		id := r.PathValue("id")
		if id == "" {
			adminError(w, http.StatusBadRequest, "missing draft id")
			return
		}

		// Read first to apply tenant scoping uniformly.
		existing, err := cfg.Store.GetDraft(r.Context(), id)
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		if err != nil {
			cfg.Logger.Error("draft pre-update get failed", "err", err, "id", id)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		if auth.tenant != "" && existing.Tenant != auth.tenant {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}

		var body draftBody
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.RegoSource) == "" {
			adminError(w, http.StatusBadRequest, "rego_source is required")
			return
		}
		if err := compilePolicy(r.Context(), body.RegoSource); err != nil {
			adminError(w, http.StatusBadRequest, "rego compile error: "+err.Error())
			return
		}

		updated, err := cfg.Store.UpdateDraft(r.Context(), policystore.Draft{
			ID:          id,
			Name:        body.Name,
			Description: body.Description,
			RegoSource:  body.RegoSource,
		})
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		if err != nil {
			cfg.Logger.Error("draft update failed", "err", err, "id", id)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(updated)
	})
}

// NewAdminDraftDeleteHandler returns DELETE /v1/admin/policies/drafts/{id}.
//
// Returns 409 when the draft is currently active (or the rollback
// target), preserving the operator's ability to un-pin via promote
// or rollback first.
func NewAdminDraftDeleteHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}

		id := r.PathValue("id")
		if id == "" {
			adminError(w, http.StatusBadRequest, "missing draft id")
			return
		}

		// Tenant pre-check via Get; cross-tenant attempt looks like 404.
		existing, err := cfg.Store.GetDraft(r.Context(), id)
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		if err != nil {
			cfg.Logger.Error("draft pre-delete get failed", "err", err, "id", id)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		if auth.tenant != "" && existing.Tenant != auth.tenant {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}

		switch err := cfg.Store.DeleteDraft(r.Context(), id); {
		case err == nil:
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
		case errors.Is(err, policystore.ErrNotFound):
			adminError(w, http.StatusNotFound, "draft not found")
		case errors.Is(err, policystore.ErrActiveDraftDelete):
			adminError(w, http.StatusConflict,
				"draft is the current or previous active policy; promote a different draft or rollback first")
		default:
			cfg.Logger.Error("draft delete failed", "err", err, "id", id)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
		}
	})
}

// activeResponse is the GET /v1/admin/policies/active body. The
// active pointer plus (when set) the metadata of the current draft
// so the console can render "currently live: <name> (id=...)".
type activeResponse struct {
	Active        policystore.Active `json:"active"`
	CurrentDraft  *policystore.Draft `json:"current_draft,omitempty"`
	PreviousDraft *policystore.Draft `json:"previous_draft,omitempty"`
	// Source describes where the live policy came from. One of:
	//   "embedded" — embedded default (no promote has happened)
	//   "file"     — INTENTGATE_POLICY_FILE was set at startup
	//   "draft"    — a promoted draft (Active.CurrentDraftID set)
	//   "fallback" — this tenant hasn't promoted; the default-
	//                fallback slot's draft serves their requests
	// Computed by the handler from the active pointer + the
	// gateway's startup config; the console renders a badge keyed
	// off this string.
	Source string `json:"source"`
}

// NewAdminActiveGetHandler returns GET /v1/admin/policies/active.
//
// Tenant scoping:
//
//   - Per-tenant admin: tenant is forced from the resolved token;
//     ?tenant= disagreeing returns 403.
//   - Superadmin: ?tenant=X scopes to X; omitted/empty returns the
//     default-fallback row.
//
// When the requested tenant has no promoted policy of its own but
// the default-fallback row IS populated, the response reports
// source="fallback" along with the fallback draft so the console
// can render "you're seeing the default-fallback policy because
// this tenant hasn't promoted one".
func NewAdminActiveGetHandler(cfg PolicyAdminConfig, startupSource string) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}

		tenant := r.URL.Query().Get("tenant")
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		a, err := cfg.Store.GetActive(r.Context(), tenant)
		if err != nil {
			cfg.Logger.Error("active get failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		resp := activeResponse{Active: a, Source: startupSource}
		if a.CurrentDraftID != "" {
			d, err := cfg.Store.GetDraft(r.Context(), a.CurrentDraftID)
			if err == nil {
				resp.CurrentDraft = &d
			}
			resp.Source = "draft"
		} else if tenant != "" {
			// This tenant hasn't promoted. If the default-fallback
			// row has a draft, that's what the gateway evaluates
			// their requests against — surface it.
			def, derr := cfg.Store.GetActive(r.Context(), "")
			if derr == nil && def.CurrentDraftID != "" {
				if d, gerr := cfg.Store.GetDraft(r.Context(), def.CurrentDraftID); gerr == nil {
					resp.CurrentDraft = &d
				}
				resp.Source = "fallback"
			}
		}
		if a.PreviousDraftID != "" {
			d, err := cfg.Store.GetDraft(r.Context(), a.PreviousDraftID)
			if err == nil {
				resp.PreviousDraft = &d
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// (promoteBody removed in v1.5; the per-tenant variant
// promoteBodyWithTenant lives near NewAdminPromoteHandler above.)

// NewAdminActiveDeleteHandler returns DELETE /v1/admin/policies/active.
//
// Clears the caller's tenant slot in the policystore + the live
// Reloader, so subsequent /v1/mcp requests from that tenant fall
// back to the default-fallback policy. Useful for "revert this
// tenant to platform default" without rolling back through every
// previous draft.
//
// Tenant scoping mirrors the rest of the per-tenant admin API:
//
//   - Per-tenant admin: tenant forced from the resolved token;
//     ?tenant= disagreeing returns 403.
//   - Superadmin: ?tenant=X clears X's slot. ?tenant=  (empty) is
//     a no-op on the store side (the default-fallback row is
//     special) but still returns 200 with the current state — the
//     console keys off this for the "revert to default" affordance.
//
// Emits an audit event so SOC has a record of the clear, same
// pattern as promote/rollback.
func NewAdminActiveDeleteHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}
		if cfg.Reloader == nil {
			adminError(w, http.StatusServiceUnavailable, "policy reloader not configured")
			return
		}

		tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		cleared, err := cfg.Store.DeleteActive(r.Context(), tenant)
		if err != nil {
			cfg.Logger.Error("active delete failed", "err", err, "tenant", tenant)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		// Drop the local reloader slot too. The cross-replica
		// listener handles sibling replicas via the NOTIFY emitted
		// by DeleteActive. Empty tenant is a no-op on the reloader
		// (RemoveFor("") is documented as a no-op).
		if tenant != "" {
			cfg.Reloader.RemoveFor(tenant)
		}

		// Audit: like promote/rollback, the operator label goes in
		// Reason rather than AgentID.
		ev := audit.NewEvent(audit.DecisionAllow, "admin/clear_policy")
		ev.Check = audit.CheckPolicy
		ev.Reason = "policy slot cleared: tenant=" + tenant
		ev.Tenant = tenant
		ev.RemoteIP = r.RemoteAddr
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("policy slot cleared", "tenant", tenant)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"cleared": cleared,
			"swapped": tenant != "",
		})
	})
}

// promoteBody adds an optional tenant field so superadmins can
// promote against any tenant's slot. Per-tenant admins have their
// tenant forced from the resolved token; cross-tenant attempts
// return 403 the same way the mint handler does.
type promoteBodyWithTenant struct {
	DraftID    string `json:"draft_id"`
	PromotedBy string `json:"promoted_by"`
	Tenant     string `json:"tenant,omitempty"`
}

// NewAdminPromoteHandler returns POST /v1/admin/policies/active.
//
// Compiles the target draft's Rego, swaps it into the live
// Reloader's per-tenant slot, writes the active-pointer row,
// emits an audit event. Per-tenant admins promote against their
// own tenant; superadmins promote against body.tenant (defaulting
// to the empty/default-fallback slot, preserving v1.4 single-
// tenant behavior).
//
// Cross-tenant attempts by per-tenant admins return 403 — the
// resolved tenant from the constant-time admin auth wins.
func NewAdminPromoteHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}
		if cfg.Reloader == nil {
			adminError(w, http.StatusServiceUnavailable,
				"policy reloader not configured; gateway cannot hot-swap policies in this deployment")
			return
		}

		var body promoteBodyWithTenant
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.DraftID) == "" {
			adminError(w, http.StatusBadRequest, "draft_id is required")
			return
		}

		// Tenant resolution: per-tenant admin's tenant wins; body
		// tenant disagreement returns 403. Superadmin honors body
		// verbatim (empty body.tenant = the default-fallback slot,
		// which preserves the v1.4 single-engine semantic).
		tenant := strings.TrimSpace(body.Tenant)
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in body does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		// Load draft + compile BEFORE we touch the active pointer.
		// If the compile fails, we want to leave the gateway running
		// the prior policy and surface the error to the operator.
		d, err := cfg.Store.GetDraft(r.Context(), body.DraftID)
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		if err != nil {
			cfg.Logger.Error("promote get draft failed", "err", err, "id", body.DraftID)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		// Cross-tenant draft selection by a per-tenant admin is also
		// a 404 (don't leak existence). A superadmin promoting a
		// draft from any tenant onto any tenant's slot is allowed —
		// drafts are tenant-scoped storage, but the active pointer
		// is just a reference to compiled Rego, not a tenant claim.
		if auth.tenant != "" && d.Tenant != auth.tenant {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		newEngine, err := policy.NewEngine(r.Context(), d.RegoSource)
		if err != nil {
			adminError(w, http.StatusBadRequest, "rego compile error: "+err.Error())
			return
		}

		active, err := cfg.Store.Promote(r.Context(), body.DraftID, body.PromotedBy, tenant)
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusNotFound, "draft not found")
			return
		}
		if err != nil {
			cfg.Logger.Error("promote failed", "err", err, "id", body.DraftID)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		// Pointer write succeeded; flip the compiled engine on the
		// hot path so subsequent requests for this tenant evaluate
		// against the new rules. SwapFor with empty tenant updates
		// the default-fallback engine (v1.4 path); with a non-empty
		// tenant it installs / updates that tenant's slot in the
		// reloader's map.
		if _, swapErr := cfg.Reloader.SwapFor(tenant, newEngine); swapErr != nil {
			cfg.Logger.Error("reloader swap failed after promote",
				"err", swapErr, "id", body.DraftID, "tenant", tenant)
			adminError(w, http.StatusInternalServerError,
				"promote recorded but engine swap failed: "+swapErr.Error())
			return
		}

		ev := audit.NewEvent(audit.DecisionAllow, "admin/promote_policy")
		ev.Check = audit.CheckPolicy
		ev.Reason = "policy promoted: tenant=" + tenant +
			" draft=" + body.DraftID +
			" prior=" + active.PreviousDraftID +
			" by=" + body.PromotedBy
		ev.Tenant = tenant
		ev.RemoteIP = r.RemoteAddr
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("policy promoted",
			"tenant", tenant,
			"draft_id", body.DraftID, "previous_draft_id", active.PreviousDraftID,
			"promoted_by", body.PromotedBy)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":      active,
			"swapped":     true,
			"promoted_at": time.Now().UTC().Format(time.RFC3339),
		})
	})
}

// rollbackBody is the request shape for POST /v1/admin/policies/rollback.
type rollbackBody struct {
	RolledBackBy string `json:"rolled_back_by"`
	Tenant       string `json:"tenant,omitempty"`
}

// NewAdminRollbackHandler returns POST /v1/admin/policies/rollback.
//
// Swaps Current ↔ Previous on the given tenant's active pointer,
// recompiles the target draft's source, swaps the live engine in
// that tenant's reloader slot. Per-tenant admins rollback their
// own tenant; superadmins specify body.tenant (empty = default
// fallback). Returns 404 when there is nothing to roll back to.
func NewAdminRollbackHandler(cfg PolicyAdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg.adminConfig())
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Store == nil {
			adminError(w, http.StatusServiceUnavailable, "policy store not configured")
			return
		}
		if cfg.Reloader == nil {
			adminError(w, http.StatusServiceUnavailable,
				"policy reloader not configured")
			return
		}

		var body rollbackBody
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		// Empty body is fine — both fields are optional.
		_ = dec.Decode(&body)

		tenant := strings.TrimSpace(body.Tenant)
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in body does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		// Read active first so we can fetch the target draft before
		// the rollback flips the pointer. Doing it before lets us
		// compile-fail cleanly without leaving the active pointer
		// in an inconsistent state.
		current, err := cfg.Store.GetActive(r.Context(), tenant)
		if err != nil {
			cfg.Logger.Error("rollback get active failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		if current.PreviousDraftID == "" {
			adminError(w, http.StatusNotFound,
				"no previous policy to roll back to")
			return
		}

		targetDraft, err := cfg.Store.GetDraft(r.Context(), current.PreviousDraftID)
		if errors.Is(err, policystore.ErrNotFound) {
			adminError(w, http.StatusServiceUnavailable,
				"previous draft is missing from the store (likely deleted)")
			return
		}
		if err != nil {
			cfg.Logger.Error("rollback get target draft failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		newEngine, err := policy.NewEngine(r.Context(), targetDraft.RegoSource)
		if err != nil {
			adminError(w, http.StatusBadRequest, "rego compile error: "+err.Error())
			return
		}

		active, err := cfg.Store.Rollback(r.Context(), body.RolledBackBy, tenant)
		if errors.Is(err, policystore.ErrNotFound) {
			// Race: someone else rolled back between our read and
			// our write.
			adminError(w, http.StatusNotFound,
				"no previous policy to roll back to")
			return
		}
		if err != nil {
			cfg.Logger.Error("rollback failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		if _, swapErr := cfg.Reloader.SwapFor(tenant, newEngine); swapErr != nil {
			cfg.Logger.Error("reloader swap failed after rollback",
				"err", swapErr, "tenant", tenant)
			adminError(w, http.StatusInternalServerError,
				"rollback recorded but engine swap failed: "+swapErr.Error())
			return
		}

		ev := audit.NewEvent(audit.DecisionAllow, "admin/rollback_policy")
		ev.Check = audit.CheckPolicy
		ev.Reason = "policy rolled back to: tenant=" + tenant +
			" draft=" + active.CurrentDraftID +
			" by=" + body.RolledBackBy
		ev.Tenant = tenant
		ev.RemoteIP = r.RemoteAddr
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("policy rolled back",
			"tenant", tenant,
			"new_current_draft_id", active.CurrentDraftID,
			"rolled_back_by", body.RolledBackBy)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":  active,
			"swapped": true,
		})
	})
}
