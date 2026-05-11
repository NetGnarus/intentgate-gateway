-- IntentGate policy-draft + active-pointer schema.
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.
--
-- # History
--
-- gateway 1.4.0  Initial: policy_drafts + policy_active.
--
-- # Layout
--
-- policy_drafts holds operator-authored Rego candidates. tenant is
-- NOT NULL (defaults to '' for superadmin-authored drafts) so
-- per-tenant queries can filter on it cleanly. We index
-- (tenant, updated_at DESC) because the dominant query is the
-- console's draft-list view, which is exactly that shape.
--
-- policy_active is a single-row pointer table with the literal
-- 'global' as its only valid id. Using a known string for the PK
-- rather than a NULL or omitted constraint means every gateway
-- replica reads and writes the same row, the active-pointer update
-- is a single UPSERT, and the schema documents "one active per
-- gateway install" at the table level. Per-tenant active policies
-- are a planned follow-on; when that lands, this table will gain a
-- tenant column and the PK becomes (id, tenant). For v1.4 the
-- single-row shape matches the gateway's single-engine semantics.

CREATE TABLE IF NOT EXISTS policy_drafts (
    id           TEXT NOT NULL PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    rego_source  TEXT NOT NULL,
    tenant       TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS policy_drafts_tenant_updated_at_idx
    ON policy_drafts (tenant, updated_at DESC);

CREATE TABLE IF NOT EXISTS policy_active (
    id                 TEXT NOT NULL PRIMARY KEY,
    current_draft_id   TEXT NOT NULL DEFAULT '',
    previous_draft_id  TEXT NOT NULL DEFAULT '',
    promoted_at        TIMESTAMPTZ,
    promoted_by        TEXT NOT NULL DEFAULT ''
);

-- Seed the single 'global' row so the application code can use
-- plain UPDATEs after a fresh install without first checking
-- whether the row exists. ON CONFLICT keeps this idempotent.
INSERT INTO policy_active (id) VALUES ('global')
    ON CONFLICT (id) DO NOTHING;
