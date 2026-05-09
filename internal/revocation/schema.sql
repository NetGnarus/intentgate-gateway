-- Revocation table for IntentGate capability tokens.
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS revoked_tokens_revoked_at_idx
    ON revoked_tokens (revoked_at DESC);
