-- Audit-event store for IntentGate.
--
-- One row per gateway authorization decision. Schema mirrors the
-- audit.Event Go struct (see internal/audit/audit.go) — every field on
-- the wire has a column here so a SIEM-style query (filter by agent,
-- tool, decision, time range) doesn't need to rehydrate JSON.
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.

CREATE TABLE IF NOT EXISTS audit_events (
    id                   BIGSERIAL PRIMARY KEY,
    -- Wall-clock timestamp emitted by the gateway. NOT NULL because
    -- every audit.Event.Timestamp is populated by NewEvent().
    ts                   TIMESTAMPTZ NOT NULL,
    -- Stable event-name string for downstream routing
    -- (e.g. "intentgate.tool_call"). Indexed because most queries are
    -- "give me decisions" and we want the planner to skip non-decision
    -- events without a sequential scan when other event names land.
    event_name           TEXT NOT NULL DEFAULT 'intentgate.tool_call',
    schema_version       TEXT NOT NULL DEFAULT '1',

    -- Verdict + which check fired.
    decision             TEXT NOT NULL,
    check_stage          TEXT NOT NULL DEFAULT '',
    reason               TEXT NOT NULL DEFAULT '',

    -- Actor.
    agent_id             TEXT NOT NULL DEFAULT '',
    session_id           TEXT NOT NULL DEFAULT '',

    -- Resource.
    tool                 TEXT NOT NULL DEFAULT '',
    -- arg_keys is a small list (handful of strings); JSONB keeps it
    -- queryable without a separate table.
    arg_keys             JSONB,

    -- Capability identity.
    capability_token_id  TEXT NOT NULL DEFAULT '',
    intent_summary       TEXT NOT NULL DEFAULT '',

    -- Operational telemetry.
    latency_ms           BIGINT NOT NULL DEFAULT 0,
    remote_ip            TEXT NOT NULL DEFAULT '',
    upstream_status      INTEGER NOT NULL DEFAULT 0
);

-- Most queries are "events for an agent in a window" or "blocks in a
-- window"; both filter on ts. Descending so LIMIT N grabs the newest
-- without a sort.
CREATE INDEX IF NOT EXISTS audit_events_ts_idx
    ON audit_events (ts DESC);

-- Per-agent paging in the compliance pack and the OSS audit viewer.
CREATE INDEX IF NOT EXISTS audit_events_agent_ts_idx
    ON audit_events (agent_id, ts DESC)
    WHERE agent_id <> '';

-- Per-tool paging — useful for "what did the email_send tool do?".
CREATE INDEX IF NOT EXISTS audit_events_tool_ts_idx
    ON audit_events (tool, ts DESC)
    WHERE tool <> '';

-- Quick "blocks only" filter, the most common SOC-investigation query.
CREATE INDEX IF NOT EXISTS audit_events_decision_ts_idx
    ON audit_events (decision, ts DESC);

-- Correlate an incident back to a token's lifetime.
CREATE INDEX IF NOT EXISTS audit_events_jti_ts_idx
    ON audit_events (capability_token_id, ts DESC)
    WHERE capability_token_id <> '';
