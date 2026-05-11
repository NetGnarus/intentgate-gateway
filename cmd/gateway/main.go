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
//	INTENTGATE_AUDIT_PERSIST        "true" to also persist every audit
//	                                event into the configured Postgres
//	                                (uses INTENTGATE_POSTGRES_URL). When
//	                                set, GET /v1/admin/audit becomes
//	                                queryable. Default off so existing
//	                                stdout-only deployments are unchanged.
//	INTENTGATE_SIEM_SPLUNK_URL      Splunk HEC endpoint URL. When set
//	                                with INTENTGATE_SIEM_SPLUNK_TOKEN,
//	                                every audit event also ships to
//	                                Splunk in batches.
//	INTENTGATE_SIEM_SPLUNK_TOKEN    Splunk HEC token (header value).
//	INTENTGATE_SIEM_SPLUNK_INDEX    Optional Splunk index. Empty routes
//	                                to the token's default index.
//	INTENTGATE_SIEM_DATADOG_API_KEY When set, every audit event also
//	                                ships to Datadog Logs Intake.
//	INTENTGATE_SIEM_DATADOG_SITE    Datadog regional site, default
//	                                "datadoghq.com".
//	INTENTGATE_SIEM_DATADOG_SERVICE Datadog "service" tag, default
//	                                "intentgate-gateway".
//	INTENTGATE_SIEM_SENTINEL_DCE_URL    Microsoft Sentinel Data
//	                                Collection Endpoint URL.
//	INTENTGATE_SIEM_SENTINEL_DCR_ID  Immutable ID of the Data
//	                                Collection Rule.
//	INTENTGATE_SIEM_SENTINEL_STREAM  Custom-table stream name, e.g.
//	                                "Custom-IntentGate_CL".
//	INTENTGATE_SIEM_SENTINEL_TENANT_ID    Azure AD tenant.
//	INTENTGATE_SIEM_SENTINEL_CLIENT_ID    Service-principal client ID.
//	INTENTGATE_SIEM_SENTINEL_CLIENT_SECRET  Service-principal secret.
//	                                All six are required together;
//	                                missing any disables the Sentinel
//	                                emitter (or fails fast if some
//	                                but not all are set).
//	INTENTGATE_APPROVALS_BACKEND   "memory" (default), "postgres", or
//	                                "off". When "postgres" the gateway
//	                                uses INTENTGATE_POSTGRES_URL for
//	                                the queue. "off" disables the
//	                                escalate path: a Rego policy
//	                                returning escalate becomes a block.
//	INTENTGATE_APPROVAL_TIMEOUT_S  How long the gateway waits for a
//	                                human decision before timing out
//	                                and returning block. Default 300
//	                                (5 minutes).
//	INTENTGATE_POLICY_STORE        "off" (default), "memory", or
//	                                "postgres". When "memory" or
//	                                "postgres", /v1/admin/policies/*
//	                                draft and active-pointer endpoints
//	                                register. "postgres" uses
//	                                INTENTGATE_POSTGRES_URL. Promotes
//	                                survive restarts only on
//	                                "postgres".
//	INTENTGATE_TENANT_ADMINS       Comma-separated tenant:token pairs
//	                                that scope admin operations to a
//	                                single tenant.
//	                                Example: "acme:tok-a,globex:tok-b".
//	                                Coexists with INTENTGATE_ADMIN_TOKEN
//	                                (the superadmin); a deployment can
//	                                set both, neither, or just one.
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
//	INTENTGATE_METRICS_ENABLED      "true" to register /metrics on the
//	                                public port. Default off because
//	                                exposing metrics on the same port
//	                                as agent traffic is an info-
//	                                disclosure risk for naive deploys.
//	OTEL_EXPORTER_OTLP_ENDPOINT     standard OTel env var. When set,
//	                                the gateway initializes an OTLP
//	                                gRPC exporter and emits one span
//	                                per HTTP request. Empty disables
//	                                tracing entirely (no overhead).
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
	"strings"
	"syscall"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/approvals"
	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/NetGnarus/intentgate-gateway/internal/auditstore"
	"github.com/NetGnarus/intentgate-gateway/internal/budget"
	"github.com/NetGnarus/intentgate-gateway/internal/capability"
	"github.com/NetGnarus/intentgate-gateway/internal/extractor"
	"github.com/NetGnarus/intentgate-gateway/internal/metrics"
	"github.com/NetGnarus/intentgate-gateway/internal/policy"
	"github.com/NetGnarus/intentgate-gateway/internal/policystore"
	"github.com/NetGnarus/intentgate-gateway/internal/revocation"
	"github.com/NetGnarus/intentgate-gateway/internal/server"
	"github.com/NetGnarus/intentgate-gateway/internal/siem"
	"github.com/NetGnarus/intentgate-gateway/internal/upstream"
	"github.com/NetGnarus/intentgate-gateway/internal/webhook"
	"github.com/redis/go-redis/v9"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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
	auditPersist := envOr("INTENTGATE_AUDIT_PERSIST", "") == "true"
	auditArgValuesRaw := envOr("INTENTGATE_AUDIT_PERSIST_ARG_VALUES", "")
	argRedaction, argRedactionErr := audit.ParseRedactionMode(auditArgValuesRaw)
	if argRedactionErr != nil {
		logger.Error("invalid INTENTGATE_AUDIT_PERSIST_ARG_VALUES", "err", argRedactionErr)
		os.Exit(1)
	}
	splunkURL := envOr("INTENTGATE_SIEM_SPLUNK_URL", "")
	splunkToken := envOr("INTENTGATE_SIEM_SPLUNK_TOKEN", "")
	splunkIndex := envOr("INTENTGATE_SIEM_SPLUNK_INDEX", "")
	datadogAPIKey := envOr("INTENTGATE_SIEM_DATADOG_API_KEY", "")
	datadogSite := envOr("INTENTGATE_SIEM_DATADOG_SITE", "")
	datadogService := envOr("INTENTGATE_SIEM_DATADOG_SERVICE", "")
	sentinelDCEURL := envOr("INTENTGATE_SIEM_SENTINEL_DCE_URL", "")
	sentinelDCRID := envOr("INTENTGATE_SIEM_SENTINEL_DCR_ID", "")
	sentinelStream := envOr("INTENTGATE_SIEM_SENTINEL_STREAM", "")
	sentinelTenantID := envOr("INTENTGATE_SIEM_SENTINEL_TENANT_ID", "")
	sentinelClientID := envOr("INTENTGATE_SIEM_SENTINEL_CLIENT_ID", "")
	sentinelClientSecret := envOr("INTENTGATE_SIEM_SENTINEL_CLIENT_SECRET", "")
	// Webhook fan-out (Pro v2 #3). URL is the operator-configured
	// receiver — typically a console-pro endpoint that re-routes
	// per-tenant to Slack / Teams / PagerDuty. Empty disables the
	// emitter entirely (no Pro tier check at the gateway layer;
	// console-pro gates which channels the operator can configure).
	webhookURL := envOr("INTENTGATE_WEBHOOK_URL", "")
	webhookSecret := envOr("INTENTGATE_WEBHOOK_SECRET", "")
	webhookEventsRaw := envOr("INTENTGATE_WEBHOOK_EVENTS", "")
	approvalsBackend := envOr("INTENTGATE_APPROVALS_BACKEND", "memory")
	approvalTimeoutS := envOr("INTENTGATE_APPROVAL_TIMEOUT_S", "300")
	// Policy-store backend: "off" disables the draft + promote /
	// rollback flow entirely (older deployments stay unchanged).
	// "memory" is the dev default — drafts live in-process and are
	// lost on restart, fine for kicking the tires. "postgres" is
	// the production default once a Postgres URL is configured.
	policyStoreBackend := envOr("INTENTGATE_POLICY_STORE", "off")
	tenantAdminsRaw := envOr("INTENTGATE_TENANT_ADMINS", "")
	upstreamURL := envOr("INTENTGATE_UPSTREAM_URL", "")
	upstreamTimeoutMS := envOr("INTENTGATE_UPSTREAM_TIMEOUT_MS", "")
	postgresURL := envOr("INTENTGATE_POSTGRES_URL", "")
	adminToken := envOr("INTENTGATE_ADMIN_TOKEN", "")
	metricsEnabled := envOr("INTENTGATE_METRICS_ENABLED", "") == "true"
	otelEndpoint := envOr("OTEL_EXPORTER_OTLP_ENDPOINT", "")

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
	// Wrap the initial engine in a Reloader so promote / rollback
	// can swap it at runtime. Static deployments that never promote
	// pay nothing for the indirection (atomic-pointer load per
	// request is single-digit nanoseconds).
	policyReloader := policy.NewReloader(policyEngine)

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

	// Optional Postgres-backed audit persistence. Layered as a fan-out
	// on top of whatever auditTarget produced so existing stdout-only
	// deployments keep their log-shipper pipelines unchanged.
	auditStore, auditStoreEmitter, auditStoreDesc, err := loadAuditStore(
		context.Background(), logger, postgresURL, auditPersist,
	)
	if err != nil {
		logger.Error("failed to initialize audit store", "err", err)
		os.Exit(1)
	}
	if auditStoreEmitter != nil {
		auditEmitter = audit.NewFanOut(auditEmitter, auditStoreEmitter)
		auditDesc = auditDesc + "+" + auditStoreDesc
	}

	siemEmitters, siemReporters, siemDesc, err := loadSIEM(logger, siemEnv{
		splunkURL:            splunkURL,
		splunkToken:          splunkToken,
		splunkIndex:          splunkIndex,
		datadogAPIKey:        datadogAPIKey,
		datadogSite:          datadogSite,
		datadogService:       datadogService,
		sentinelDCEURL:       sentinelDCEURL,
		sentinelDCRID:        sentinelDCRID,
		sentinelStream:       sentinelStream,
		sentinelTenantID:     sentinelTenantID,
		sentinelClientID:     sentinelClientID,
		sentinelClientSecret: sentinelClientSecret,
	})
	if err != nil {
		logger.Error("failed to initialize SIEM emitters", "err", err)
		os.Exit(1)
	}
	if len(siemEmitters) > 0 {
		all := []audit.Emitter{auditEmitter}
		for _, e := range siemEmitters {
			all = append(all, e)
		}
		auditEmitter = audit.NewFanOut(all...)
		auditDesc = auditDesc + "+" + siemDesc
	}

	// Webhook emitter (Pro v2 #3). Peer of the SIEM emitters in the
	// fan-out: same Emit-must-not-block contract, separate buffer
	// and worker, dropped events surface as counters on the admin
	// /v1/admin/integrations response.
	webhookEmitter, webhookDesc, err := loadWebhook(logger, webhookURL, webhookSecret, webhookEventsRaw)
	if err != nil {
		logger.Error("failed to initialize webhook emitter", "err", err)
		os.Exit(1)
	}
	if webhookEmitter != nil {
		auditEmitter = audit.NewFanOut(auditEmitter, webhookEmitter)
		auditDesc = auditDesc + "+" + webhookDesc
	}

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Drain SIEM emitters first so any tail-end events make it
		// to Splunk / Datadog before the process exits.
		for _, e := range siemEmitters {
			if s, ok := e.(siem.Stoppable); ok {
				_ = s.Stop(shutdownCtx)
			}
		}
		if webhookEmitter != nil {
			_ = webhookEmitter.Stop(shutdownCtx)
		}
		if auditStoreEmitter != nil {
			_ = auditStoreEmitter.Stop(shutdownCtx)
		}
		if auditStore != nil {
			_ = auditStore.Close()
		}
	}()

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

	approvalsStore, approvalsDesc, err := loadApprovals(context.Background(), logger, approvalsBackend, postgresURL)
	if err != nil {
		logger.Error("failed to initialize approvals store", "err", err)
		os.Exit(1)
	}
	defer func() {
		if approvalsStore != nil {
			_ = approvalsStore.Close()
		}
	}()

	approvalTimeout, err := parseApprovalTimeout(approvalTimeoutS)
	if err != nil {
		logger.Error("INTENTGATE_APPROVAL_TIMEOUT_S invalid", "err", err)
		os.Exit(1)
	}

	policyStore, policyStoreDesc, err := loadPolicyStore(context.Background(), logger, policyStoreBackend, postgresURL)
	if err != nil {
		logger.Error("failed to initialize policy store", "err", err)
		os.Exit(1)
	}
	defer func() {
		if policyStore != nil {
			_ = policyStore.Close()
		}
	}()

	// On startup, if the policy store already has a promoted draft,
	// load its source and swap the reloader to it BEFORE the server
	// starts taking traffic. This makes promotions survive gateway
	// restarts — otherwise a pod recycle would silently fall back to
	// the embedded default / INTENTGATE_POLICY_FILE policy.
	startupPolicySource, err := reloadActivePolicy(context.Background(), logger, policyStore, policyReloader, policySource)
	if err != nil {
		logger.Error("failed to load active policy from store", "err", err)
		os.Exit(1)
	}

	// Cross-replica policy refresh. Subscribe to active-pointer
	// changes so a promote / rollback on a sibling replica swaps
	// THIS replica's compiled engine in near-real-time, instead of
	// only on pod restart. No-op when policyStore is nil.
	//
	// Seed the watcher with the per-tenant current draft ids so
	// its first polling-fallback delivery (which always fires
	// within pollFallbackInterval of start) doesn't log a
	// misleading "swapped from sibling replica" line for state
	// this pod already loaded at startup.
	startupDraftIDs := make(map[string]string)
	if policyStore != nil {
		if rows, lErr := policyStore.ListActive(context.Background()); lErr == nil {
			for _, a := range rows {
				if a.CurrentDraftID != "" {
					startupDraftIDs[a.Tenant] = a.CurrentDraftID
				}
			}
		}
	}
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	if policyStore != nil {
		go watchAndReloadPolicy(watchCtx, logger, policyStore, policyReloader, startupDraftIDs)
	}

	adminTokenDesc := "disabled"
	if adminToken != "" {
		adminTokenDesc = "configured"
	}

	tenantAdmins, err := parseTenantAdmins(tenantAdminsRaw)
	if err != nil {
		logger.Error("INTENTGATE_TENANT_ADMINS invalid", "err", err)
		os.Exit(1)
	}
	tenantAdminsDesc := "none"
	if n := len(tenantAdmins); n > 0 {
		tenantAdminsDesc = fmt.Sprintf("%d tenant(s)", n)
	}

	metricsHandle := metrics.New(metrics.Config{IncludeRuntimeMetrics: metricsEnabled})

	otelShutdown, otelDesc, err := loadTracing(context.Background(), version, otelEndpoint)
	if err != nil {
		logger.Error("failed to initialize OTel tracing", "err", err)
		os.Exit(1)
	}
	defer func() {
		if otelShutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = otelShutdown(ctx)
		}
	}()

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
		"tenant_admins", tenantAdminsDesc,
		"approvals", approvalsDesc,
		"policy_store", policyStoreDesc,
		"metrics_endpoint", metricsEnabled,
		"otel_tracing", otelDesc,
	)

	srv := server.New(server.Config{
		Addr:                  addr,
		Logger:                logger,
		Version:               version,
		MasterKey:             masterKey,
		RequireCapability:     requireCap,
		Extractor:             extractorClient,
		RequireIntent:         requireIntent,
		Policy:                policyReloader,
		Budget:                budgetStore,
		RequireBudget:         requireBudget,
		Audit:                 auditEmitter,
		AuditStore:            auditStore,
		SIEMReporters:         siemReporters,
		Upstream:              upstreamClient,
		Revocation:            revocationStore,
		Approvals:             approvalsStore,
		ApprovalTimeout:       approvalTimeout,
		ArgRedaction:          argRedaction,
		PolicyStore:           policyStore,
		PolicyReloader:        policyReloader,
		PolicySource:          startupPolicySource,
		TenantAdmins:          tenantAdmins,
		AdminToken:            adminToken,
		Metrics:               metricsHandle,
		EnableMetricsEndpoint: metricsEnabled,
		EnableOTelTracing:     otelEndpoint != "",
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

// loadTracing initializes the OpenTelemetry tracer provider when an
// OTLP endpoint is configured. Returns a shutdown function the caller
// must call on graceful exit so in-flight spans flush.
//
// We deliberately don't start a sampler / metric pipeline here — the
// SDK defaults (always-on sampling, no metric pipeline) are fine for
// v1. Operators with high-RPS deployments can add their own sampler
// via standard OTEL_TRACES_SAMPLER env vars; the SDK reads them.
func loadTracing(ctx context.Context, version, endpoint string) (func(context.Context) error, string, error) {
	if endpoint == "" {
		return nil, "disabled", nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, "", fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("intentgate-gateway"),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		return nil, "", fmt.Errorf("otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, fmt.Sprintf("enabled (otlp grpc: %s)", endpoint), nil
}

// siemEnv groups the SIEM-related environment variables so loadSIEM
// has a small, stable signature.
type siemEnv struct {
	splunkURL            string
	splunkToken          string
	splunkIndex          string
	datadogAPIKey        string
	datadogSite          string
	datadogService       string
	sentinelDCEURL       string
	sentinelDCRID        string
	sentinelStream       string
	sentinelTenantID     string
	sentinelClientID     string
	sentinelClientSecret string
}

// loadSIEM constructs whichever SIEM emitters the operator has wired
// via env vars. Returns:
//
//   - emitters    : audit.Emitter slice ready to drop into the fan-out
//   - reporters   : siem.StatusReporter slice for the admin endpoint
//   - description : human-readable summary used in the startup log
//
// A misconfigured destination (e.g. SPLUNK_URL set without
// SPLUNK_TOKEN) returns an error so the gateway fails fast instead
// of silently dropping events.
func loadSIEM(logger *slog.Logger, env siemEnv) ([]audit.Emitter, []siem.StatusReporter, string, error) {
	var emitters []audit.Emitter
	var reporters []siem.StatusReporter
	var labels []string

	if env.splunkURL != "" || env.splunkToken != "" {
		if env.splunkURL == "" || env.splunkToken == "" {
			return nil, nil, "", fmt.Errorf("INTENTGATE_SIEM_SPLUNK_URL and INTENTGATE_SIEM_SPLUNK_TOKEN must both be set")
		}
		em, err := siem.NewSplunkEmitter(siem.SplunkConfig{
			URL:    env.splunkURL,
			Token:  env.splunkToken,
			Index:  env.splunkIndex,
			Logger: logger,
		})
		if err != nil {
			return nil, nil, "", err
		}
		emitters = append(emitters, em)
		reporters = append(reporters, em)
		labels = append(labels, "splunk")
		logger.Info("SIEM emitter: splunk", "url", env.splunkURL, "index", env.splunkIndex)
	}

	if env.datadogAPIKey != "" {
		em, err := siem.NewDatadogEmitter(siem.DatadogConfig{
			APIKey:  env.datadogAPIKey,
			Site:    env.datadogSite,
			Service: env.datadogService,
			Logger:  logger,
		})
		if err != nil {
			return nil, nil, "", err
		}
		emitters = append(emitters, em)
		reporters = append(reporters, em)
		labels = append(labels, "datadog")
		logger.Info("SIEM emitter: datadog", "site", env.datadogSite)
	}

	if anySentinelSet := env.sentinelDCEURL != "" ||
		env.sentinelDCRID != "" || env.sentinelStream != "" ||
		env.sentinelTenantID != "" || env.sentinelClientID != "" ||
		env.sentinelClientSecret != ""; anySentinelSet {
		em, err := siem.NewSentinelEmitter(siem.SentinelConfig{
			DCEUrl:         env.sentinelDCEURL,
			DCRImmutableID: env.sentinelDCRID,
			StreamName:     env.sentinelStream,
			TenantID:       env.sentinelTenantID,
			ClientID:       env.sentinelClientID,
			ClientSecret:   env.sentinelClientSecret,
			Logger:         logger,
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("sentinel: %w", err)
		}
		emitters = append(emitters, em)
		reporters = append(reporters, em)
		labels = append(labels, "sentinel")
		logger.Info("SIEM emitter: sentinel",
			"dce", env.sentinelDCEURL,
			"dcr", env.sentinelDCRID,
			"stream", env.sentinelStream)
	}

	desc := "none"
	if len(labels) > 0 {
		desc = strings.Join(labels, ",")
	}
	return emitters, reporters, desc, nil
}

// loadWebhook constructs the optional webhook emitter. Returns
// (nil, "disabled", nil) when INTENTGATE_WEBHOOK_URL is unset —
// webhook fan-out is fully opt-in. When the URL IS set, we
// validate the secret (warning when empty, since unsigned webhooks
// can be spoofed by anyone who knows the receiver URL) and parse
// the optional events allowlist.
func loadWebhook(logger *slog.Logger, url, secret, eventsRaw string) (*webhook.Emitter, string, error) {
	if strings.TrimSpace(url) == "" {
		return nil, "disabled", nil
	}
	parsedSecret, err := webhook.MustParseSecret(secret)
	if err != nil {
		return nil, "", fmt.Errorf("INTENTGATE_WEBHOOK_SECRET: %w", err)
	}
	if len(parsedSecret) == 0 {
		logger.Warn("webhook configured without a signing secret; receivers cannot verify authenticity",
			"hint", "set INTENTGATE_WEBHOOK_SECRET to a 32-byte hex string")
	}

	sink, err := webhook.NewHTTPSink(webhook.HTTPSinkConfig{
		URL:    url,
		Secret: parsedSecret,
		Logger: logger,
	})
	if err != nil {
		return nil, "", fmt.Errorf("webhook sink: %w", err)
	}

	var allowed []string
	if eventsRaw != "" {
		for _, s := range strings.Split(eventsRaw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				allowed = append(allowed, s)
			}
		}
	}

	em := webhook.NewEmitter(webhook.EmitterConfig{
		Sink:   sink,
		Filter: webhook.DefaultFilter(allowed),
		Logger: logger,
	})
	logger.Info("webhook emitter configured",
		"url", url,
		"signed", len(parsedSecret) > 0,
		"events_filter", eventsRaw,
	)
	return em, "webhook", nil
}

// loadAuditStore constructs the optional Postgres-backed audit store
// and its async emitter. Returns (nil, nil, "disabled", nil) when
// audit persistence isn't enabled or no Postgres URL is configured —
// the gateway runs fine with stdout-only audit, and we don't want to
// half-enable persistence (which would silently degrade the
// /v1/admin/audit endpoint to "always empty").
func loadAuditStore(ctx context.Context, logger *slog.Logger, postgresURL string, persist bool) (auditstore.Store, *auditstore.Emitter, string, error) {
	if !persist {
		return nil, nil, "disabled", nil
	}
	if postgresURL == "" {
		// Persist=true without a DSN is operator error: a misconfigured
		// gateway will look "audit-persistent" in dashboards but lose
		// every event. Refuse to start.
		return nil, nil, "", fmt.Errorf("INTENTGATE_AUDIT_PERSIST=true requires INTENTGATE_POSTGRES_URL")
	}
	store, err := auditstore.NewPostgresStore(ctx, postgresURL)
	if err != nil {
		return nil, nil, "", err
	}
	em := auditstore.NewEmitter(auditstore.EmitterConfig{
		Store:  store,
		Logger: logger,
	})
	logger.Info("audit store: postgres", "persist", true)
	return store, em, "postgres", nil
}

// parseTenantAdmins reads INTENTGATE_TENANT_ADMINS into a map.
//
// Format: "tenant1:token1,tenant2:token2". Whitespace around each
// component is trimmed; entries with empty tenant or empty token are
// rejected at startup so a typo doesn't silently lock out an admin.
// Tokens MUST NOT contain commas (encoded if needed) or colons in
// the tenant name; the parser refuses ambiguous inputs.
func parseTenantAdmins(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, ":")
		if idx <= 0 || idx == len(pair)-1 {
			return nil, fmt.Errorf("entry %q must be in tenant:token format", pair)
		}
		tenant := strings.TrimSpace(pair[:idx])
		token := strings.TrimSpace(pair[idx+1:])
		if tenant == "" || token == "" {
			return nil, fmt.Errorf("entry %q has empty tenant or token", pair)
		}
		if _, dup := out[tenant]; dup {
			return nil, fmt.Errorf("duplicate tenant %q in TENANT_ADMINS", tenant)
		}
		out[tenant] = token
	}
	return out, nil
}

// loadApprovals constructs the human-approval queue.
//
//	backend = "off"      → returns (nil, "off", nil) — escalate becomes block.
//	backend = "memory"   → in-process queue, single replica only.
//	backend = "postgres" → durable queue at INTENTGATE_POSTGRES_URL.
//
// A misconfigured backend ("postgres" without a DSN) returns an error
// so the gateway fails fast.
func loadApprovals(ctx context.Context, logger *slog.Logger, backend, postgresURL string) (approvals.Store, string, error) {
	switch backend {
	case "off":
		logger.Info("approvals queue: disabled")
		return nil, "off", nil
	case "", "memory":
		logger.Info("approvals queue: in-memory (single-replica only, lost on restart)")
		return approvals.NewMemoryStore(), "memory", nil
	case "postgres":
		if postgresURL == "" {
			return nil, "", fmt.Errorf("INTENTGATE_APPROVALS_BACKEND=postgres requires INTENTGATE_POSTGRES_URL")
		}
		store, err := approvals.NewPostgresStore(ctx, postgresURL)
		if err != nil {
			return nil, "", err
		}
		logger.Info("approvals queue: postgres")
		return store, "postgres", nil
	default:
		return nil, "", fmt.Errorf("unknown INTENTGATE_APPROVALS_BACKEND %q (want off|memory|postgres)", backend)
	}
}

// parseApprovalTimeout converts the seconds-as-string env var into a
// duration. Empty / 0 falls back to 5 minutes; negative is rejected.
func parseApprovalTimeout(s string) (time.Duration, error) {
	if s == "" {
		return 5 * time.Minute, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("must be >= 0, got %d", n)
	}
	if n == 0 {
		return 5 * time.Minute, nil
	}
	return time.Duration(n) * time.Second, nil
}

// loadPolicyStore constructs the optional draft + active-pointer
// store backing /v1/admin/policies/*.
//
//	backend = "off"      → returns (nil, "off", nil); draft endpoints
//	                       aren't registered. Existing deployments
//	                       upgrading to v1.4 see no change unless they
//	                       explicitly opt in.
//	backend = "memory"   → in-process MemoryStore, fine for dev / smoke.
//	backend = "postgres" → durable PostgresStore at the existing
//	                       INTENTGATE_POSTGRES_URL.
//
// Misconfiguration (postgres without a DSN) is a fail-fast.
func loadPolicyStore(ctx context.Context, logger *slog.Logger, backend, postgresURL string) (policystore.Store, string, error) {
	switch backend {
	case "", "off":
		logger.Info("policy store: disabled",
			"hint", "set INTENTGATE_POLICY_STORE=memory (dev) or postgres (prod) to enable /v1/admin/policies/*")
		return nil, "off", nil
	case "memory":
		logger.Info("policy store: in-memory (single-replica only, lost on restart)")
		return policystore.NewMemoryStore(), "memory", nil
	case "postgres":
		if postgresURL == "" {
			return nil, "", fmt.Errorf("INTENTGATE_POLICY_STORE=postgres requires INTENTGATE_POSTGRES_URL")
		}
		store, err := policystore.NewPostgresStore(ctx, postgresURL)
		if err != nil {
			return nil, "", err
		}
		logger.Info("policy store: postgres")
		return store, "postgres", nil
	default:
		return nil, "", fmt.Errorf("unknown INTENTGATE_POLICY_STORE %q (want off|memory|postgres)", backend)
	}
}

// reloadActivePolicy hydrates the policy reloader from the store
// at startup so promotions survive gateway restarts. v1.5 makes
// this per-tenant: every populated active row gets its target
// draft compiled and installed in the reloader's matching slot.
// The default-fallback row (tenant="") drives the reloader's
// default engine, preserving v1.4 single-tenant semantics for
// deployments that haven't promoted any per-tenant overlays.
//
// Returns the startup-source label fed back to the
// /v1/admin/policies/active handler so the console knows whether
// the gateway is currently running an embedded default, a file-
// supplied policy, or a promoted draft.
//
// When the store is nil (INTENTGATE_POLICY_STORE=off) we leave the
// reloader untouched and return the fallback source.
//
// When any active row's recompile fails, we log loudly and refuse
// to start: the gateway running the embedded default while the
// database says "policy X is live for tenant Y" is exactly the
// kind of confusion auditors flag, so failing fast is correct.
func reloadActivePolicy(ctx context.Context, logger *slog.Logger, store policystore.Store, reloader *policy.Reloader, fallbackSource string) (string, error) {
	if store == nil {
		return fallbackSource, nil
	}
	rows, err := store.ListActive(ctx)
	if err != nil {
		return "", fmt.Errorf("list active policies: %w", err)
	}
	// Track whether the default-fallback slot got populated from
	// the store, vs left at the startup-bootstrap engine (embedded
	// default or INTENTGATE_POLICY_FILE).
	defaultHydratedFromStore := false
	tenantsLoaded := 0

	for _, active := range rows {
		if active.CurrentDraftID == "" {
			continue
		}
		draft, err := store.GetDraft(ctx, active.CurrentDraftID)
		if err != nil {
			return "", fmt.Errorf("load active draft %q (tenant=%q): %w",
				active.CurrentDraftID, active.Tenant, err)
		}
		engine, err := policy.NewEngine(ctx, draft.RegoSource)
		if err != nil {
			return "", fmt.Errorf("compile active draft %q (tenant=%q): %w",
				active.CurrentDraftID, active.Tenant, err)
		}
		if _, err := reloader.SwapFor(active.Tenant, engine); err != nil {
			return "", fmt.Errorf("swap to active draft %q (tenant=%q): %w",
				active.CurrentDraftID, active.Tenant, err)
		}
		logger.Info("loaded promoted policy from store",
			"tenant", active.Tenant,
			"draft_id", active.CurrentDraftID,
			"name", draft.Name,
			"promoted_at", active.PromotedAt,
			"promoted_by", active.PromotedBy,
		)
		if active.Tenant == "" {
			defaultHydratedFromStore = true
		} else {
			tenantsLoaded++
		}
	}

	if tenantsLoaded > 0 {
		logger.Info("policy reloader hydrated per-tenant overlays",
			"tenants_loaded", tenantsLoaded,
			"default_from_store", defaultHydratedFromStore)
	}
	if defaultHydratedFromStore {
		return "draft", nil
	}
	if tenantsLoaded > 0 {
		// Some tenants have their own policy but the default slot
		// still uses the startup bootstrap. Label reflects that the
		// "live" answer depends on the calling tenant.
		return fallbackSource + " + per-tenant overlays", nil
	}
	logger.Info("policy store has no active drafts; using fallback policy",
		"fallback_source", fallbackSource)
	return fallbackSource, nil
}

// watchAndReloadPolicy is the cross-replica refresh loop. It
// subscribes to the policy store's Watch channel and, for every
// active-pointer change observed (either via Postgres NOTIFY from
// a sibling replica or via the polling fallback), fetches the
// referenced draft, compiles it, and Swaps the live engine.
//
// Reliability semantics:
//
//   - Idempotent. If the incoming active.CurrentDraftID matches what
//     we last loaded, the swap is skipped — no compile, no engine
//     churn. Handles both "redundant NOTIFY after a no-op promote"
//     and "polling fallback fires on an unchanged active".
//   - Compile failures DON'T crash the gateway. A draft that
//     somehow lands in the active row with broken Rego is logged
//     loudly and the in-flight engine keeps serving traffic. The
//     admin endpoint compiles on save AND on promote, so the only
//     way to get here is a manual DB poke or a deeply weird race.
//   - The loop exits when the Watch channel closes (store Close
//     during shutdown OR ctx cancelled).
//
// The startup-time [reloadActivePolicy] hydration already covers
// "what's currently active" before the server takes traffic; this
// watcher only handles changes that happen WHILE the gateway is
// running.
//
// startupDraftIDs is a per-tenant seed for the de-dup map: the
// first polling-fallback delivery for each tenant slot recognizes
// the state this pod already loaded at startup as a no-op and
// skips the re-compile + misleading "swapped from sibling" log
// line.
func watchAndReloadPolicy(ctx context.Context, logger *slog.Logger, store policystore.Store, reloader *policy.Reloader, startupDraftIDs map[string]string) {
	ch, err := store.Watch(ctx)
	if err != nil {
		logger.Error("policy watcher failed to subscribe; cross-replica refresh disabled",
			"err", err)
		return
	}
	logger.Info("policy watcher started",
		"seeded_tenants", len(startupDraftIDs))

	// Per-tenant last-applied tracking. Seeded from startup so we
	// don't re-load what reloadActivePolicy already installed.
	lastApplied := make(map[string]string, len(startupDraftIDs))
	for tenant, id := range startupDraftIDs {
		lastApplied[tenant] = id
	}

	for active := range ch {
		if active.CurrentDraftID == "" {
			// DeleteActive signal. For a per-tenant slot, drop it
			// so subsequent requests from that tenant fall back to
			// the default. For the default-fallback slot, no-op:
			// clearing the default would leave the gateway with
			// nothing to serve — the store's DeleteActive enforces
			// that on the write path too, but defense-in-depth.
			if active.Tenant != "" {
				reloader.RemoveFor(active.Tenant)
				delete(lastApplied, active.Tenant)
				logger.Info("policy watcher: tenant slot cleared from sibling replica",
					"tenant", active.Tenant)
			}
			continue
		}
		if active.CurrentDraftID == lastApplied[active.Tenant] {
			continue
		}

		draft, err := store.GetDraft(ctx, active.CurrentDraftID)
		if err != nil {
			logger.Error("policy watcher: failed to read promoted draft; keeping current engine",
				"draft_id", active.CurrentDraftID, "tenant", active.Tenant, "err", err)
			continue
		}
		engine, err := policy.NewEngine(ctx, draft.RegoSource)
		if err != nil {
			logger.Error("policy watcher: failed to compile promoted draft; keeping current engine",
				"draft_id", active.CurrentDraftID, "tenant", active.Tenant, "err", err)
			continue
		}
		if _, err := reloader.SwapFor(active.Tenant, engine); err != nil {
			logger.Error("policy watcher: engine swap failed; keeping current engine",
				"draft_id", active.CurrentDraftID, "tenant", active.Tenant, "err", err)
			continue
		}
		lastApplied[active.Tenant] = active.CurrentDraftID
		logger.Info("policy watcher: swapped to promoted draft from sibling replica",
			"tenant", active.Tenant,
			"draft_id", active.CurrentDraftID,
			"promoted_at", active.PromotedAt,
			"promoted_by", active.PromotedBy,
		)
	}
	logger.Info("policy watcher stopped")
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
