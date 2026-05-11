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
    upstream_status      INTEGER NOT NULL DEFAULT 0,

    -- Delegation telemetry (audit schema_version 2, gateway 0.7+).
    -- root_capability_token_id correlates events from a delegation
    -- chain. caveat_count is a coarse "how attenuated is this token"
    -- signal. Both NULL-default so the migration is no-op on
    -- already-deployed tables and old rows simply read NULL.
    root_capability_token_id TEXT,
    caveat_count             INTEGER,

    -- Multi-tenant scoping (audit schema_version 3, gateway 0.9+).
    -- NULL-default so existing rows read NULL; new rows always carry
    -- a tenant (defaults to 'default' on the gateway side).
    tenant                   TEXT,

    -- Redacted argument values (audit schema_version 4, gateway 1.3+).
    -- Populated only when the gateway is configured with
    -- INTENTGATE_AUDIT_PERSIST_ARG_VALUES=scalars (or =raw).
    -- JSONB so dry-run + the compliance pack can read it back into
    -- map[string]any without a separate join, and so SIEM exporters
    -- can ship it verbatim. NULL on every row written by a gateway
    -- not opted into the feature, which is the v1.0-1.2 default.
    arg_values               JSONB,

    -- Tamper-evident hash chain (Pro v2 #4, gateway 1.7+).
    -- Each row's hash = SHA-256(prev_hash_or_empty || canonical_json).
    -- prev_hash is NULL on the very first row of a tenant's chain.
    -- Pre-feature rows (gateway < 1.7) have hash = '' which is how
    -- the verify endpoint distinguishes "covered by the chain" from
    -- "best-effort audit before chain was enabled".
    prev_hash                TEXT,
    hash                     TEXT NOT NULL DEFAULT ''
);

-- Idempotent ALTERs: existing 0.5/0.6 deployments whose audit_events
-- table predates these columns get them added on next start. New
-- deployments hit no-ops.
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS root_capability_token_id TEXT;
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS caveat_count INTEGER;
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS tenant TEXT;
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS arg_values JSONB;
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';

-- Per-tenant chain heads. One row per tenant; locked FOR UPDATE on
-- every insert to serialize chain progression and prevent two
-- concurrent emitter workers from forking the chain.
--
-- tenant '' is the legitimate single-tenant key; the gateway always
-- stamps a non-empty tenant on new events (default = 'default'), so
-- empty here would indicate a misconfigured caller.
CREATE TABLE IF NOT EXISTS audit_chain_heads (
    tenant      TEXT NOT NULL PRIMARY KEY,
    head_hash   TEXT NOT NULL DEFAULT '',
    head_id     BIGINT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-tenant timeline. Multi-tenant deployments filter on this
-- frequently: "show me all decisions in tenant=acme last hour".
CREATE INDEX IF NOT EXISTS audit_events_tenant_ts_idx
    ON audit_events (tenant, ts DESC)
    WHERE tenant IS NOT NULL;

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
