// Command gateway is the entrypoint for the IntentGate gateway.
//
// The gateway sits between AI agents and tool servers. It accepts tool-call
// requests over HTTP, evaluates them through the four-check pipeline
// (capability, intent, policy, budget), and either forwards the call to the
// upstream tool server or blocks it.
//
// In v0.1.0-dev the capability check is wired up; intent, policy, and
// budget land in subsequent sessions. Calls that pass capability are
// allowed with a stub reason.
//
// Configuration is via environment variables:
//
//	INTENTGATE_ADDR                 listen address (default ":8080")
//	INTENTGATE_MASTER_KEY           base64url HMAC key for capability tokens
//	                                (if unset, an ephemeral key is generated
//	                                and printed; tokens won't survive a
//	                                gateway restart)
//	INTENTGATE_REQUIRE_CAPABILITY   set to "true" to reject /v1/mcp calls
//	                                that don't carry a valid Bearer token
//	INTENTGATE_EXTRACTOR_URL        base URL of the intent extractor service,
//	                                e.g. "http://extractor:8090". When unset,
//	                                the intent check is disabled.
//	INTENTGATE_REQUIRE_INTENT       set to "true" to reject /v1/mcp calls
//	                                that don't carry an X-Intent-Prompt header
//	INTENTGATE_POLICY_FILE          path to a customer Rego policy file. When
//	                                unset, the embedded default policy is used.
//	INTENTGATE_REDIS_URL            Redis connection string for the budget
//	                                store, e.g. "redis://localhost:6379/0".
//	                                When unset, an in-memory store is used
//	                                (single-replica only).
//	INTENTGATE_REQUIRE_BUDGET       set to "true" to reject /v1/mcp calls
//	                                that lack a verified capability token
//	                                at the budget stage.
//	INTENTGATE_AUDIT_TARGET         where to emit audit events. Recognized
//	                                values: "stdout" (default), "none".
//	INTENTGATE_UPSTREAM_URL         URL of the downstream MCP tool server
//	                                authorized calls are forwarded to. When
//	                                unset, the gateway returns a stub allow
//	                                for any call that passes the four
//	                                checks (useful for SDK tests, smokes).
//	INTENTGATE_UPSTREAM_TIMEOUT_MS  per-call upstream timeout in
//	                                milliseconds. Default 30000.
//	INTENTGATE_POSTGRES_URL         libpq-style DSN for a Postgres-backed
//	                                revocation store, e.g.
//	                                "postgres://user:pass@host:5432/db".
//	                                When unset, an in-memory revocation
//	                                store is used (single-replica only,
//	                                lost on restart).
//	INTENTGATE_ADMIN_TOKEN          shared secret guarding /v1/admin/*
//	                                endpoints (revoke, list-revocations).
//	                                When unset, admin endpoints are
//	                                disabled (404 / not registered).
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/budget"
	"github.com/NetGnarus/intentgate-gateway/internal/capability"
	"github.com/NetGnarus/intentgate-gateway/internal/extractor"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
	"github.com/NetGnarus/intentgate-gateway/internal/server"
	"github.com/NetGnarus/intentgate-gateway/internal/upstream"
	"github.com/redis/go-redis/v9"
)

// version is overridden at build time via -ldflags="-X main.version=...".
var version = "0.1.0-dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	addr := envOr("INTENTGATE_ADDR", ":8080")
	requireCap := envOr("INTENTGATE_REQUIRE_CAPABILITY", "") == "true"
	requireIntent := envOr("INTENTGATE_REQUIRE_INTENT", "") == "true"
	requireBudget := envOr("INTENTGATE_REQUIRE_BUDGET", "") == "true"
	extractorURL := envOr("INTENTGATE_EXTRACTOR_URL", "")
	policyFile := envOr("INTENTGATE_POLICY_FILE", "")
	redisURL := envOr("INTENTGATE_REDIS_URL", "")
	auditTarget := envOr("INTENTGATE_AUDIT_TARGET", "stdout")
	upstreamURL := envOr("INTENTGATE_UPSTREAM_URL", "")
	upstreamTimeoutMS := envOr("INTENTGATE_UPSTREAM_TIMEOUT_MS", "")
	postgresURL := envOr("INTENTGATE_POSTGRES_URL", "")
	adminToken := envOr("INTENTGATE_ADMIN_TOKEN", "")

	masterKey, err := loadMasterKey(logger)
	if err != nil {
		logger.Error("failed to obtain master key", "err", err)
		os.Exit(1)
	}

	var extractorClient *extractor.Client
	if extractorURL != "" {
		extractorClient = extractor.New(extractorURL, 1024)
		logger.Info("intent extractor configured", "url", extractorURL)
	}

	policyEngine, policySource, err := loadPolicyEngine(logger, policyFile)
	if err != nil {
		logger.Error("failed to load policy", "err", err)
		os.Exit(1)
	}

	budgetStore, budgetSource, err := loadBudgetStore(logger, redisURL)
	if err != nil {
		logger.Error("failed to initialize budget store", "err", err)
		os.Exit(1)
	}

	auditEmitter, auditDesc, err := audit.FromTarget(auditTarget)
	if err != nil {
		logger.Error("invalid INTENTGATE_AUDIT_TARGET", "err", err)
		os.Exit(1)
	}

	upstreamClient, upstreamDesc, err := loadUpstream(logger, upstreamURL, upstreamTimeoutMS)
	if err != nil {
		logger.Error("failed to configure upstream", "err", err)
		os.Exit(1)
	}

	revocationStore, revocationDesc, err := loadRevocation(context.Background(), logger, postgresURL)
	if err != nil {
		logger.Error("failed to initialize revocation store", "err", err)
		os.Exit(1)
	}

	adminTokenDesc := "disabled"
	if adminToken != "" {
		adminTokenDesc = "configured"
	}

	logger.Info("intentgate gateway starting",
		"addr", addr,
		"version", version,
		"require_capability", requireCap,
		"require_intent", requireIntent,
		"require_budget", requireBudget,
		"intent_extractor", extractorURL != "",
		"policy_source", policySource,
		"budget_store", budgetSource,
		"audit_target", auditDesc,
		"upstream", upstreamDesc,
		"revocation_store", revocationDesc,
		"admin_api", adminTokenDesc,
	)

	srv := server.New(server.Config{
		Addr:              addr,
		Logger:            logger,
		Version:           version,
		MasterKey:         masterKey,
		RequireCapability: requireCap,
		Extractor:         extractorClient,
		RequireIntent:     requireIntent,
		Policy:            policyEngine,
		Budget:            budgetStore,
		RequireBudget:     requireBudget,
		Audit:             auditEmitter,
		Upstream:          upstreamClient,
		Revocation:        revocationStore,
		AdminToken:        adminToken,
	})

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("server failed to start", "err", err)
		os.Exit(1)
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("intentgate gateway stopped cleanly")
}

// loadMasterKey returns the master HMAC key for capability tokens.
//
// If INTENTGATE_MASTER_KEY is set, it is base64-decoded and returned.
// If unset, a fresh 32-byte key is generated, logged as a warning along
// with its base64url encoding, and returned. Tokens minted under an
// ephemeral key won't verify after a gateway restart — this is the
// intended dev-mode behavior; production deployments must set the env
// var to a stable value.
func loadMasterKey(logger *slog.Logger) ([]byte, error) {
	if s, ok := os.LookupEnv("INTENTGATE_MASTER_KEY"); ok && s != "" {
		key, err := capability.MasterKeyFromBase64(s)
		if err != nil {
			return nil, err
		}
		logger.Info("master key loaded from INTENTGATE_MASTER_KEY", "bytes", len(key))
		return key, nil
	}
	key, err := capability.NewMasterKey()
	if err != nil {
		return nil, err
	}
	logger.Warn("INTENTGATE_MASTER_KEY not set, generated ephemeral key for this run",
		"ephemeral_key_b64", base64.RawURLEncoding.EncodeToString(key),
		"hint", "set INTENTGATE_MASTER_KEY in your environment for stable tokens",
	)
	return key, nil
}

// loadPolicyEngine constructs the OPA-backed policy engine. If policyFile
// is non-empty, the file's contents are compiled as the customer's Rego
// source. Otherwise the embedded default policy is used.
//
// The returned source-description string ("file:/path" or "embedded
// default") is logged at startup so operators can confirm which policy
// is active.
func loadPolicyEngine(logger *slog.Logger, policyFile string) (*policy.Engine, string, error) {
	source := ""
	desc := "embedded default"
	if policyFile != "" {
		raw, err := os.ReadFile(policyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", policyFile, err)
		}
		source = string(raw)
		desc = "file:" + policyFile
	}
	eng, err := policy.NewEngine(context.Background(), source)
	if err != nil {
		return nil, "", err
	}
	logger.Info("policy engine ready", "source", desc, "bytes", len(source))
	return eng, desc, nil
}

// loadBudgetStore returns a budget.Store for the gateway. When
// redisURL is set, the store is backed by Redis (multi-replica safe);
// otherwise an in-memory store is used (single-replica, fine for dev).
//
// The Redis client is pinged at startup so a misconfigured URL fails
// fast instead of hiding behind the first request.
func loadBudgetStore(logger *slog.Logger, redisURL string) (budget.Store, string, error) {
	if redisURL == "" {
		logger.Info("budget store: in-memory (single-replica only)")
		return budget.NewMemoryStore(), "memory", nil
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, "", fmt.Errorf("redis parse url: %w", err)
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, "", fmt.Errorf("redis ping: %w", err)
	}
	logger.Info("budget store: redis", "addr", opts.Addr)
	return budget.NewRedisStore(client), "redis:" + opts.Addr, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// loadUpstream constructs the upstream MCP client from environment.
// Returns (nil, "stub (none)", nil) when INTENTGATE_UPSTREAM_URL is
// unset — that's the dev-friendly path where the gateway returns its
// own stub allow for any call passing the four checks.
//
// When the URL is set, the timeout is read from
// INTENTGATE_UPSTREAM_TIMEOUT_MS (default 30000), the URL is validated
// at startup so a misconfigured deployment fails fast, and the
// human-readable description used in the startup log line includes the
// URL and timeout for operator visibility.
func loadUpstream(logger *slog.Logger, url, timeoutMS string) (*upstream.Client, string, error) {
	if url == "" {
		logger.Info("upstream not configured: returning stub allow for authorized calls",
			"hint", "set INTENTGATE_UPSTREAM_URL to forward to a real MCP tool server")
		return nil, "stub (none)", nil
	}

	timeout := upstream.DefaultTimeout
	if timeoutMS != "" {
		ms, err := strconv.Atoi(timeoutMS)
		if err != nil {
			return nil, "", fmt.Errorf("INTENTGATE_UPSTREAM_TIMEOUT_MS: %w", err)
		}
		if ms <= 0 {
			return nil, "", fmt.Errorf("INTENTGATE_UPSTREAM_TIMEOUT_MS must be positive, got %d", ms)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	c, err := upstream.New(upstream.Config{URL: url, Timeout: timeout})
	if err != nil {
		return nil, "", err
	}
	return c, fmt.Sprintf("%s (timeout %s)", url, timeout), nil
}

// loadRevocation constructs the revocation store. When postgresURL is
// set, a PostgresStore is returned (with the embedded migration
// applied). Otherwise an in-memory store is used.
//
// The Postgres store keeps its own connection pool and is intentionally
// not wired into a graceful-shutdown path here — the connection pool
// will close when the process exits, which is the right behavior for
// this lightweight service. A future operator-facing graceful-shutdown
// pass should call store.Close() to flush in-flight queries cleanly.
func loadRevocation(ctx context.Context, logger *slog.Logger, postgresURL string) (revocation.Store, string, error) {
	if postgresURL == "" {
		logger.Info("revocation store: in-memory (single-replica only, lost on restart)",
			"hint", "set INTENTGATE_POSTGRES_URL for durable, multi-replica-safe revocation")
		return revocation.NewMemoryStore(), "memory", nil
	}
	store, err := revocation.NewPostgresStore(ctx, postgresURL)
	if err != nil {
		return nil, "", err
	}
	logger.Info("revocation store: postgres", "dsn_set", true)
	return store, "postgres", nil
}
