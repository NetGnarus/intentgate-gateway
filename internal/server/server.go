// Package server wires up the gateway's HTTP routes and middleware.
package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/approvals"
	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
	"github.com/NetGnarus/intentgate-gateway/internal/budget"
	"github.com/NetGnarus/intentgate-gateway/internal/extractor"
	"github.com/NetGnarus/intentgate-gateway/internal/handlers"
	"github.com/NetGnarus/intentgate-gateway/internal/metrics"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
	"github.com/NetGnarus/intentgate-gateway/internal/siem"
	"github.com/NetGnarus/intentgate-gateway/internal/upstream"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Config configures a new gateway server.
type Config struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// Logger is used for structured request logging. If nil, slog.Default is used.
	Logger *slog.Logger
	// Version is reported by /healthz.
	Version string
	// MasterKey is the HMAC key used to verify capability tokens on
	// /v1/mcp. May be nil only when RequireCapability is false.
	MasterKey []byte
	// RequireCapability rejects /v1/mcp requests that don't carry a
	// valid Bearer capability token. Default false (dev mode).
	RequireCapability bool
	// Extractor is the optional intent-extractor client. nil means no
	// intent check is performed.
	Extractor *extractor.Client
	// RequireIntent rejects /v1/mcp requests that don't carry an
	// X-Intent-Prompt header. Default false (dev mode).
	RequireIntent bool
	// Policy is the OPA-backed policy engine. nil means the policy
	// check is skipped (dev convenience).
	Policy *policy.Engine
	// Budget is the per-token call counter store. nil means the
	// budget check is skipped (dev convenience). Production deployments
	// supply a Redis-backed implementation; dev deployments fall back
	// to an in-memory one.
	Budget budget.Store
	// RequireBudget rejects calls without a verified capability token
	// from reaching the budget stage. Default false (dev mode).
	RequireBudget bool
	// Audit is the emitter for one-event-per-decision audit records.
	// nil falls back to a NullEmitter (no events emitted).
	Audit audit.Emitter
	// AuditStore is the queryable backing store the admin audit
	// endpoint reads from. nil means audit persistence is disabled
	// (the route is not registered, so /v1/admin/audit returns 404 on
	// older / lighter deployments).
	AuditStore auditstore.Store
	// SIEMReporters provides the read-only status snapshots the
	// /v1/admin/integrations endpoint surfaces. One reporter per
	// configured SIEM destination; empty slice means no SIEM
	// integrations are wired (the route is registered anyway so the
	// console can render "not configured" cards).
	SIEMReporters []siem.StatusReporter
	// Approvals is the human-approval queue. nil disables both the
	// in-pipeline escalate path and the /v1/admin/approvals routes.
	Approvals approvals.Store
	// ApprovalTimeout caps how long the gateway waits for a human
	// decision before timing out and returning block. Zero falls
	// back to the handler's default (5 minutes).
	ApprovalTimeout time.Duration
	// Upstream is the configured downstream MCP tool server. nil means
	// no upstream is configured and the gateway returns its stub allow
	// for authorized calls. Production deployments always supply one.
	Upstream *upstream.Client
	// Revocation is the store the capability check consults to reject
	// tokens revoked after issuance. nil means the revocation step is
	// skipped (dev convenience). Production supplies a real store.
	Revocation revocation.Store
	// AdminToken is the shared secret the /v1/admin/* endpoints check
	// in constant time. When empty, admin endpoints are disabled.
	AdminToken string
	// Metrics is the Prometheus instrumentation. nil disables both the
	// /metrics endpoint and per-handler observation calls (handlers
	// guard against nil internally).
	Metrics *metrics.Metrics
	// EnableMetricsEndpoint registers GET /metrics serving the
	// Metrics handler. Off by default so naive deployments don't
	// expose internal metrics on the public port.
	EnableMetricsEndpoint bool
	// EnableOTelTracing wraps the HTTP handler with otelhttp so each
	// request becomes a span. Configuration of the exporter is via
	// standard OTEL_* env vars; this flag only toggles the middleware.
	EnableOTelTracing bool
}

// New constructs an *http.Server with all gateway routes and middleware.
// The returned server is ready for ListenAndServe.
func New(cfg Config) *http.Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()

	// Health probe — used by Kubernetes liveness/readiness checks and by
	// operators verifying the binary is up.
	mux.Handle("GET /healthz", handlers.NewHealthHandler(cfg.Version))

	// Tool-call ingress, REST shape — kept for ad-hoc curl testing.
	// Same stub behavior as the MCP endpoint, simpler request body.
	mux.Handle("POST /v1/tool-call", handlers.NewToolCallHandler(logger))

	// MCP ingress, JSON-RPC 2.0 shape — the canonical contract for
	// MCP-speaking clients (LangChain, Anthropic SDK with MCP, custom).
	// In v0.1 this handles "tools/call" only with the capability check;
	// other methods return JSON-RPC MethodNotFound until upstream
	// proxying lands.
	mux.Handle("POST /v1/mcp", handlers.NewMCPHandler(handlers.MCPHandlerConfig{
		Logger:            logger,
		MasterKey:         cfg.MasterKey,
		RequireCapability: cfg.RequireCapability,
		Extractor:         cfg.Extractor,
		RequireIntent:     cfg.RequireIntent,
		Policy:            cfg.Policy,
		Budget:            cfg.Budget,
		RequireBudget:     cfg.RequireBudget,
		Audit:             cfg.Audit,
		Upstream:          cfg.Upstream,
		Revocation:        cfg.Revocation,
		Metrics:           cfg.Metrics,
		Approvals:         cfg.Approvals,
		ApprovalTimeout:   cfg.ApprovalTimeout,
	}))

	// Prometheus scrape endpoint. Behind a flag because exposing
	// internal metrics on the public API port is an info-disclosure
	// risk for naive deployments. Operators who scrape via a
	// sidecar / service mesh / private network flip this on.
	if cfg.EnableMetricsEndpoint && cfg.Metrics != nil {
		mux.Handle("GET /metrics", cfg.Metrics.Handler())
	}

	// Admin API. Wired in only when an admin token is configured;
	// without one, every request would fail 401 anyway and exposing
	// the routes adds no value. With one, the operator (or admin UI)
	// can revoke tokens and inspect the revocation list.
	if cfg.AdminToken != "" {
		adminCfg := handlers.AdminConfig{
			Logger:     logger,
			AdminToken: cfg.AdminToken,
			MasterKey:  cfg.MasterKey,
			Revocation: cfg.Revocation,
			Audit:      cfg.Audit,
		}
		mux.Handle("POST /v1/admin/revoke", handlers.NewAdminRevokeHandler(adminCfg))
		mux.Handle("GET /v1/admin/revocations", handlers.NewAdminRevocationsListHandler(adminCfg))
		mux.Handle("POST /v1/admin/mint", handlers.NewAdminMintHandler(adminCfg))
		// Audit query is registered only when an AuditStore is wired
		// in. Older deployments running stdout-only audit get a 404,
		// which is what the console keys off to fall back to its
		// upload-based flow.
		if cfg.AuditStore != nil {
			adminCfg.AuditStore = cfg.AuditStore
			mux.Handle("GET /v1/admin/audit", handlers.NewAdminAuditQueryHandler(adminCfg))
		}
		// Integrations endpoint always registered when an admin token
		// is set: returns an empty array when no SIEM is wired, which
		// the console renders as "no integrations configured" rather
		// than a 404.
		adminCfg.SIEMReporters = cfg.SIEMReporters
		mux.Handle("GET /v1/admin/integrations", handlers.NewAdminIntegrationsHandler(adminCfg))
		// Approvals endpoints register only when a queue is wired.
		// Older / lighter deployments without escalation get a 404,
		// which the console renders as "feature not enabled".
		if cfg.Approvals != nil {
			adminCfg.Approvals = cfg.Approvals
			mux.Handle("GET /v1/admin/approvals", handlers.NewAdminApprovalsListHandler(adminCfg))
			mux.Handle("POST /v1/admin/approvals/{id}/decide", handlers.NewAdminApprovalsDecideHandler(adminCfg))
		}
	}

	handler := chain(mux,
		recoverer(logger),      // outermost: catches panics from any handler
		requestLogger(logger),  // logs every request after it completes
		metricsMiddleware(cfg), // observe every request into prom histograms
	)

	if cfg.EnableOTelTracing {
		// otelhttp creates a span per request. The route name comes
		// from go-http-mux's pattern matching; we override it via
		// otelhttp.WithSpanNameFormatter for cleaner span names.
		handler = otelhttp.NewHandler(handler, "http.server",
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return r.Method + " " + r.URL.Path
			}),
		)
	}

	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// chain composes middleware so that the first argument runs outermost.
// chain(h, A, B) yields a handler that calls A → B → h.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// requestLogger logs method, path, status, latency, and remote address for
// every request once it completes.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"latency_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr,
			)
		})
	}
}

// recoverer recovers panics from downstream handlers, logs them, and returns
// a 500 to the client. Without this, a panic would crash the server.
func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					logger.Error("panic in handler",
						"panic", v,
						"path", r.URL.Path,
						"method", r.Method,
					)
					http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status code so
// the request logger can include it in the log line.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// metricsMiddleware records every request into the Prometheus
// histograms / counters. Route is the URL path collapsed to a known
// label set so we don't blow up cardinality on path-encoded data.
//
// When cfg.Metrics is nil, the middleware is a no-op.
func metricsMiddleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Metrics == nil {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			cfg.Metrics.ObserveHTTP(r.Method, routeLabel(r.URL.Path), rec.status, time.Since(start))
		})
	}
}

// routeLabel collapses an arbitrary request path into one of the
// gateway's known routes. Anything else folds into "other" so we
// never emit unbounded path-shaped labels.
func routeLabel(path string) string {
	switch path {
	case "/healthz", "/v1/tool-call", "/v1/mcp", "/metrics",
		"/v1/admin/revoke", "/v1/admin/revocations", "/v1/admin/mint",
		"/v1/admin/audit", "/v1/admin/integrations",
		"/v1/admin/approvals":
		return path
	}
	// /v1/admin/approvals/{id}/decide collapses to a fixed label so
	// the metrics histogram doesn't blow up cardinality on the id.
	if strings.HasPrefix(path, "/v1/admin/approvals/") && strings.HasSuffix(path, "/decide") {
		return "/v1/admin/approvals/decide"
	}
	return "other"
}
