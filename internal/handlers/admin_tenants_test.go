package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fixture: build a tenants list handler with the canonical two-tenant
// + superadmin config.
func newTenantsHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "super",
		TenantAdmins: map[string]string{
			"acme":   "tok-acme",
			"globex": "tok-globex",
			// Empty token slots are configured but not active. The
			// handler must skip them (a configured-but-unset entry is
			// not a tenant the operator can talk to).
			"unfunded": "",
		},
	}
	return NewAdminTenantsListHandler(cfg)
}

type tenantEntry struct {
	ID       string `json:"id"`
	HasAdmin bool   `json:"has_admin"`
}

type tenantsResp struct {
	Tenants []tenantEntry `json:"tenants"`
}

func TestAdminTenants_Unauthenticated(t *testing.T) {
	h := newTenantsHandler(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/admin/tenants", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no token: status=%d want 401", rr.Code)
	}
}

func TestAdminTenants_BogusToken(t *testing.T) {
	h := newTenantsHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("bogus token: status=%d want 401", rr.Code)
	}
}

func TestAdminTenants_SuperadminSeesAll(t *testing.T) {
	h := newTenantsHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants", nil)
	req.Header.Set("Authorization", "Bearer super")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("super: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got tenantsResp
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	// Two configured-and-funded tenants, sorted alphabetically.
	if len(got.Tenants) != 2 {
		t.Fatalf("super list: got %d entries want 2; got=%+v", len(got.Tenants), got.Tenants)
	}
	if got.Tenants[0].ID != "acme" || got.Tenants[1].ID != "globex" {
		t.Errorf("super list: ids=%v want [acme, globex]", []string{got.Tenants[0].ID, got.Tenants[1].ID})
	}
	for _, e := range got.Tenants {
		if !e.HasAdmin {
			t.Errorf("entry %s: has_admin=false want true", e.ID)
		}
	}
}

func TestAdminTenants_PerTenantSeesOnlyOwn(t *testing.T) {
	h := newTenantsHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants", nil)
	req.Header.Set("Authorization", "Bearer tok-acme")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("acme: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got tenantsResp
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tenants) != 1 || got.Tenants[0].ID != "acme" {
		t.Errorf("acme list: got %+v want [{acme, true}]", got.Tenants)
	}
}

func TestAdminTenants_NoTenantsConfiguredReturnsEmpty(t *testing.T) {
	// A single-tenant deploy that set no per-tenant admins. The
	// endpoint must be reachable (so the console can probe), but
	// returns an empty list — the UI hides the switcher.
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "super",
	}
	h := NewAdminTenantsListHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants", nil)
	req.Header.Set("Authorization", "Bearer super")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got tenantsResp
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tenants) != 0 {
		t.Errorf("no-tenants list: got %+v want []", got.Tenants)
	}
}
