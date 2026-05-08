// Package server wires up the gateway's HTTP routes and middleware.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/NetGnarus/intentgate-gateway-/internal/handlers"
)

// Config configures a new gateway server.
type Config struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// Logger is used for structured request logging. If nil, slog.Default is used.
	Logger *slog.Logger
	// Version is reported by /healthz.
	Version string
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
	// In v0.1 this handles "tools/call" only; other methods return
	// JSON-RPC MethodNotFound until upstream proxying lands.
	mux.Handle("POST /v1/mcp", handlers.NewMCPHandler(logger))

	handler := chain(mux,
		recoverer(logger),    // outermost: catches panics from any handler
		requestLogger(logger), // logs every request after it completes
	)

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
