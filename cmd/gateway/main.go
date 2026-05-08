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
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NetGnarus/intentgate-gateway-/internal/capability"
	"github.com/NetGnarus/intentgate-gateway-/internal/extractor"
	"github.com/NetGnarus/intentgate-gateway-/internal/server"
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
	extractorURL := envOr("INTENTGATE_EXTRACTOR_URL", "")

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

	logger.Info("intentgate gateway starting",
		"addr", addr,
		"version", version,
		"require_capability", requireCap,
		"require_intent", requireIntent,
		"intent_extractor", extractorURL != "",
	)

	srv := server.New(server.Config{
		Addr:              addr,
		Logger:            logger,
		Version:           version,
		MasterKey:         masterKey,
		RequireCapability: requireCap,
		Extractor:         extractorClient,
		RequireIntent:     requireIntent,
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

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
