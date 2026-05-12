-- Pending-approvals queue for IntentGate's high-risk human-approval
-- flow. One row per tool call that the policy engine escalated; the
-- row's lifecycle goes pending → (approved|rejected|timeout).
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.

CREATE TABLE IF NOT EXISTS pending_approvals (
    pending_id               TEXT PRIMARY KEY,

    -- Capability correlation. Both NULLABLE so dev / test rows
    -- without a verified token can still be enqueued.
    capability_token_id      TEXT,
    root_capability_token_id TEXT,

    agent_id                 TEXT NOT NULL DEFAULT '',
    tool                     TEXT NOT NULL,

    -- Args is JSONB so an operator's review UI can render structured
    -- data, not an opaque blob. Treat the whole row as sensitive at
    -- the storage layer (Postgres TDE / encrypted disks).
    args                     JSONB,
    intent_summary           TEXT NOT NULL DEFAULT '',
    reason                   TEXT NOT NULL DEFAULT '',

    -- Lifecycle.
    status                   TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'timeout')),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at               TIMESTAMPTZ,
    decided_by               TEXT NOT NULL DEFAULT '',
    decide_note              TEXT NOT NULL DEFAULT '',

    -- Tenant scope (multi-tenant, gateway 1.0+). Per-tenant admins
    -- only see / decide their own tenant's pending rows.
    tenant                   TEXT,

    -- Whether the originating tool call was flagged for step-up
    -- (Pro v2 #2 follow-up, session 59). Sourced from the Rego
    -- policy's `requires_step_up` decision at escalate time; lets
    -- the operator console route the Approve verdict through a
    -- TOTP modal rather than firing direct.
    requires_step_up         BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE pending_approvals
    ADD COLUMN IF NOT EXISTS tenant TEXT;

ALTER TABLE pending_approvals
    ADD COLUMN IF NOT EXISTS requires_step_up BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS pending_approvals_tenant_pending_idx
    ON pending_approvals (tenant, created_at DESC)
    WHERE status = 'pending' AND tenant IS NOT NULL;

-- The console's "show me the pending queue" call filters on status +
-- orders by created_at DESC. The partial index keeps lookups cheap
-- even when the historical (decided) rows accumulate.
CREATE INDEX IF NOT EXISTS pending_approvals_pending_idx
    ON pending_approvals (created_at DESC)
    WHERE status = 'pending';

-- Status filter for "show me decisions in Q2" — the historical view.
CREATE INDEX IF NOT EXISTS pending_approvals_status_created_idx
    ON pending_approvals (status, created_at DESC);

-- Per-agent timeline (audit reconstruction).
CREATE INDEX IF NOT EXISTS pending_approvals_agent_idx
    ON pending_approvals (agent_id, created_at DESC)
    WHERE agent_id <> '';
