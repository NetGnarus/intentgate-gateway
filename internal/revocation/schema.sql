-- Revocation table for IntentGate capability tokens.
--
-- Idempotent migration: applied at gateway startup. Subsequent
-- restarts against a running DB are no-ops.
--
-- # History
--
-- gateway < 1.0  PRIMARY KEY (jti), no tenant column.
-- gateway 1.0    tenant column added (NULL allowed) for List
--                attribution; PK still on jti alone.
-- gateway 1.0.1  PK becomes (jti, tenant) so per-tenant admins can
--                each maintain their own revocation row for the same
--                JTI without one stomping the other. NULL tenants are
--                backfilled to '' so the column can be NOT NULL and
--                participate in the composite PK. The empty string ''
--                is the canonical "superadmin / global" tenant on the
--                hot path: IsRevoked(jti, T) returns true if either a
--                row with tenant=T exists OR a row with tenant=''
--                exists, so a superadmin revoke still affects every
--                tenant the way it did before.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason     TEXT NOT NULL DEFAULT '',
    tenant     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (jti, tenant)
);

-- 1.0 -> 1.0.1 column add (no-op once present): older deployments
-- that ran 1.0 first see the column already.
ALTER TABLE revoked_tokens
    ADD COLUMN IF NOT EXISTS tenant TEXT;

-- 1.0 -> 1.0.1 backfill: any row revoked under 1.0 has tenant=NULL.
-- We treat those as superadmin revocations (apply globally), so
-- backfilling to '' preserves their existing semantics under the
-- new IsRevoked(jti, T) lookup.
UPDATE revoked_tokens SET tenant = '' WHERE tenant IS NULL;

-- 1.0 -> 1.0.1 NOT NULL + default: safe after the backfill above.
ALTER TABLE revoked_tokens
    ALTER COLUMN tenant SET DEFAULT '';
ALTER TABLE revoked_tokens
    ALTER COLUMN tenant SET NOT NULL;

-- 1.0 -> 1.0.1 primary-key migration. Drop the old PK on (jti) only
-- if it's still in place, then add the composite. The DO block makes
-- this idempotent: a 1.0.1 gateway starting against a 1.0.1 DB
-- finds revoked_tokens_pkey already on (jti, tenant) and leaves it.
DO $$
DECLARE
    pk_cols TEXT;
BEGIN
    SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum))
    INTO pk_cols
    FROM pg_constraint c
    JOIN pg_attribute  a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
    WHERE c.conrelid = 'revoked_tokens'::regclass AND c.contype = 'p';

    IF pk_cols = 'jti' THEN
        ALTER TABLE revoked_tokens DROP CONSTRAINT revoked_tokens_pkey;
        ALTER TABLE revoked_tokens ADD PRIMARY KEY (jti, tenant);
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS revoked_tokens_revoked_at_idx
    ON revoked_tokens (revoked_at DESC);

-- The old partial index (WHERE tenant IS NOT NULL) becomes a plain
-- composite index now that tenant is NOT NULL. Drop the partial form
-- if it exists so the planner doesn't carry both.
DROP INDEX IF EXISTS revoked_tokens_tenant_revoked_at_idx;
CREATE INDEX IF NOT EXISTS revoked_tokens_tenant_revoked_at_idx2
    ON revoked_tokens (tenant, revoked_at DESC);
