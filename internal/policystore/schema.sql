-- IntentGate policy-draft + active-pointer schema.
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.
--
-- # History
--
-- gateway 1.4.0  Initial: policy_drafts + policy_active. policy_active
--                had a single 'global' row keyed by literal id; one
--                policy engine per gateway install.
-- gateway 1.5.0  policy_active becomes per-tenant. The PK changes
--                from (id) to (tenant). Existing 'global' rows
--                migrate to tenant='' (the new "default fallback"
--                slot, semantically identical to v1.4's single row).
--                Per-tenant admins now promote against their own
--                tenant slot; the gateway's reloader dispatches
--                each request to the right compiled engine based on
--                the verified capability token's tenant claim.

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

-- Fresh installs land here with PK on (tenant) directly (the v1.5
-- shape). The DO block below still handles v1.4→v1.5 PK migration
-- for deployments that started against an older schema where the PK
-- was on (id).
--
-- Without the PK on the CREATE TABLE, the bottom-of-file seed's
-- `INSERT ... ON CONFLICT (tenant) DO NOTHING` fails on fresh
-- postgres with SQLSTATE 42P10 because nothing made (tenant) unique.
CREATE TABLE IF NOT EXISTS policy_active (
    id                 TEXT NOT NULL,
    tenant             TEXT NOT NULL DEFAULT '',
    current_draft_id   TEXT NOT NULL DEFAULT '',
    previous_draft_id  TEXT NOT NULL DEFAULT '',
    promoted_at        TIMESTAMPTZ,
    promoted_by        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant)
);

-- 1.4 -> 1.5 column add (no-op once present). Pre-1.5 deployments
-- had only `id` as the PK; we add the tenant column, backfill, then
-- swap the PK.
ALTER TABLE policy_active
    ADD COLUMN IF NOT EXISTS tenant TEXT;
UPDATE policy_active
    SET tenant = ''
    WHERE tenant IS NULL;
ALTER TABLE policy_active
    ALTER COLUMN tenant SET DEFAULT '';
ALTER TABLE policy_active
    ALTER COLUMN tenant SET NOT NULL;

-- 1.4 -> 1.5 PK migration. Drop the old PK on (id) only if it's
-- still in place, then add the new PK on (tenant). The DO block
-- makes this idempotent: a 1.5 gateway starting against a 1.5 DB
-- finds the PK already on (tenant) and leaves it.
DO $$
DECLARE
    pk_cols TEXT;
BEGIN
    SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum))
    INTO pk_cols
    FROM pg_constraint c
    JOIN pg_attribute  a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
    WHERE c.conrelid = 'policy_active'::regclass AND c.contype = 'p';

    IF pk_cols = 'id' THEN
        ALTER TABLE policy_active DROP CONSTRAINT policy_active_pkey;
        ALTER TABLE policy_active ADD PRIMARY KEY (tenant);
    END IF;
END$$;

-- The `id` column is kept (it's NOT NULL DEFAULT '') for migration
-- compatibility; queries operate on (tenant) only. A future schema
-- pass can drop it once we're sure no downgrade path is needed.

-- Seed the default-fallback row if a fresh install has no rows at
-- all. ON CONFLICT keeps this idempotent across restarts and after
-- per-tenant promotes have populated other rows.
INSERT INTO policy_active (id, tenant) VALUES ('global', '')
    ON CONFLICT (tenant) DO NOTHING;
