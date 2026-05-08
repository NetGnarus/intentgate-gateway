// Package handlers contains HTTP handlers for the gateway's API surface.
package handlers

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the body returned by GET /healthz.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

type healthHandler struct {
	version string
}

// NewHealthHandler returns an http.Handler that responds 200 with a small
// JSON body. Used by Kubernetes liveness/readiness probes.
func NewHealthHandler(version string) http.Handler {
	return &healthHandler{version: version}
}

func (h *healthHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(HealthResponse{
		Status:  "ok",
		Version: h.version,
	})
}
