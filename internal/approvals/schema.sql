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
    decide_note              TEXT NOT NULL DEFAULT ''
);

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
