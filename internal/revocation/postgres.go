package revocation

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is the migration SQL applied at startup.
//
// Single table, primary key on the JTI (the lookup key on the hot
// path), descending index on revoked_at for the admin list view.
// IF NOT EXISTS keeps the migration idempotent: subsequent restarts
// against a running DB are no-ops, no migration tool needed.
//
//go:embed schema.sql
var schemaSQL string

// PostgresStore is a durable, queryable, multi-replica-safe
// revocation store backed by Postgres.
//
// Connection pooling is delegated to pgxpool. The pool is created in
// NewPostgresStore from a libpq-style DSN (postgres://user:pass@host:port/db).
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects to Postgres using the given DSN, pings to
// fail-fast on misconfig, runs the embedded migration, and returns a
// ready-to-use Store.
//
// The caller owns the *PostgresStore and must call Close when shutting
// down the gateway.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("revocation: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("revocation: parse DSN: %w", err)
	}
	// A small pool is enough — IsRevoked is a single indexed lookup.
	// Operators can override via DSN params (pool_max_conns=...).
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 10
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("revocation: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("revocation: ping: %w", err)
	}

	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("revocation: migrate: %w", err)
	}

	return &PostgresStore{pool: pool}, nil
}

// Close releases the connection pool. Safe to call multiple times.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// IsRevoked returns true if the JTI has a row in revoked_tokens.
// One indexed primary-key lookup; the cheapest query Postgres can do.
func (s *PostgresStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`
	var exists bool
	if err := s.pool.QueryRow(ctx, q, jti).Scan(&exists); err != nil {
		return false, fmt.Errorf("revocation: query: %w", err)
	}
	return exists, nil
}

// Revoke is idempotent. ON CONFLICT updates the reason but keeps the
// original revoked_at AND the original tenant — the audit story is
// "when was this first revoked, by whom", not "who touched the note
// most recently".
func (s *PostgresStore) Revoke(ctx context.Context, jti, reason, tenant string) error {
	const q = `
		INSERT INTO revoked_tokens (jti, reason, tenant)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO UPDATE SET reason = EXCLUDED.reason
	`
	if _, err := s.pool.Exec(ctx, q, jti, reason, nullableString(tenant)); err != nil {
		return fmt.Errorf("revocation: insert: %w", err)
	}
	return nil
}

// List returns recent revocations, most-recent first.
//
// tenant=="" returns ALL rows (superadmin view). A non-empty tenant
// filters to rows whose tenant column matches exactly. Rows with
// NULL tenant (legacy or superadmin-issued) are NOT visible to
// per-tenant admins.
func (s *PostgresStore) List(ctx context.Context, tenant string, limit, offset int) ([]RevokedToken, error) {
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if tenant == "" {
		q = `
			SELECT jti, revoked_at, reason, tenant
			FROM revoked_tokens
			ORDER BY revoked_at DESC
			LIMIT $1 OFFSET $2
		`
		args = []any{limit, offset}
	} else {
		q = `
			SELECT jti, revoked_at, reason, tenant
			FROM revoked_tokens
			WHERE tenant = $1
			ORDER BY revoked_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []any{tenant, limit, offset}
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("revocation: query list: %w", err)
	}
	defer rows.Close()

	out := make([]RevokedToken, 0, limit)
	for rows.Next() {
		var (
			rt    RevokedToken
			tnant *string
		)
		if err := rows.Scan(&rt.JTI, &rt.RevokedAt, &rt.Reason, &tnant); err != nil {
			return nil, fmt.Errorf("revocation: scan: %w", err)
		}
		if tnant != nil {
			rt.Tenant = *tnant
		}
		out = append(out, rt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("revocation: rows iter: %w", err)
	}
	return out, nil
}

// nullableString turns "" into nil so the database stores NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
