-- Revocation table for IntentGate capability tokens.
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason     TEXT NOT NULL DEFAULT '',

    -- Tenant scope (multi-tenant, gateway 1.0+). NULL on rows
    -- written by older gateway versions; per-tenant admin queries
    -- filter on this column, superadmin queries don't.
    tenant     TEXT
);

ALTER TABLE revoked_tokens
    ADD COLUMN IF NOT EXISTS tenant TEXT;

CREATE INDEX IF NOT EXISTS revoked_tokens_revoked_at_idx
    ON revoked_tokens (revoked_at DESC);

CREATE INDEX IF NOT EXISTS revoked_tokens_tenant_revoked_at_idx
    ON revoked_tokens (tenant, revoked_at DESC)
    WHERE tenant IS NOT NULL;
