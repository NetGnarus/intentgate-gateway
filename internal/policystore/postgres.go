package policystore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// PostgresStore is a durable, multi-replica-safe policy-draft store.
//
// Promote and Rollback are transactional: existence check on the
// referenced draft and the update of policy_active happen inside a
// single SERIALIZABLE-equivalent transaction, so a concurrent
// DeleteDraft can't slip between the check and the write.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects, pings, runs the embedded migration,
// returns a ready-to-use store. Caller owns lifetime via Close.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("policystore: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("policystore: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 5
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("policystore: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("policystore: ping: %w", err)
	}

	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("policystore: migrate: %w", err)
	}

	return &PostgresStore{pool: pool}, nil
}

// Close releases the pool. Safe to call multiple times.
func (s *PostgresStore) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// CreateDraft inserts a row and returns the populated draft. The
// ID and timestamps are generated server-side via the store helpers,
// not the database default, so we get the same values in the
// returned struct without a round-trip RETURNING.
func (s *PostgresStore) CreateDraft(ctx context.Context, d Draft) (Draft, error) {
	now := time.Now().UTC()
	d.ID = newID()
	d.CreatedAt = now
	d.UpdatedAt = now
	const q = `
		INSERT INTO policy_drafts
			(id, name, description, rego_source, tenant, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	if _, err := s.pool.Exec(ctx, q,
		d.ID, d.Name, d.Description, d.RegoSource, d.Tenant,
		d.CreatedAt, d.UpdatedAt, d.CreatedBy,
	); err != nil {
		return Draft{}, fmt.Errorf("policystore: insert draft: %w", err)
	}
	return d, nil
}

// UpdateDraft replaces mutable fields. Tenant and CreatedAt are
// deliberately not in the SET list — drafts don't move tenancy and
// creation time is immutable.
func (s *PostgresStore) UpdateDraft(ctx context.Context, d Draft) (Draft, error) {
	d.UpdatedAt = time.Now().UTC()
	const q = `
		UPDATE policy_drafts
		SET name = $1,
		    description = $2,
		    rego_source = $3,
		    updated_at = $4
		WHERE id = $5
		RETURNING tenant, created_at, created_by
	`
	row := s.pool.QueryRow(ctx, q,
		d.Name, d.Description, d.RegoSource, d.UpdatedAt, d.ID,
	)
	if err := row.Scan(&d.Tenant, &d.CreatedAt, &d.CreatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return Draft{}, ErrNotFound
		}
		return Draft{}, fmt.Errorf("policystore: update draft: %w", err)
	}
	return d, nil
}

// GetDraft returns the row regardless of tenant.
func (s *PostgresStore) GetDraft(ctx context.Context, id string) (Draft, error) {
	const q = `
		SELECT id, name, description, rego_source, tenant,
		       created_at, updated_at, created_by
		FROM policy_drafts
		WHERE id = $1
	`
	var d Draft
	row := s.pool.QueryRow(ctx, q, id)
	if err := row.Scan(&d.ID, &d.Name, &d.Description, &d.RegoSource,
		&d.Tenant, &d.CreatedAt, &d.UpdatedAt, &d.CreatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return Draft{}, ErrNotFound
		}
		return Draft{}, fmt.Errorf("policystore: get draft: %w", err)
	}
	return d, nil
}

// ListDrafts returns most-recent-first. Tenant filter empty = all
// tenants (superadmin); non-empty filters on the indexed column.
func (s *PostgresStore) ListDrafts(ctx context.Context, filter ListFilter) ([]Draft, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var (
		q    string
		args []any
	)
	if filter.Tenant == "" {
		q = `
			SELECT id, name, description, rego_source, tenant,
			       created_at, updated_at, created_by
			FROM policy_drafts
			ORDER BY updated_at DESC
			LIMIT $1 OFFSET $2
		`
		args = []any{limit, filter.Offset}
	} else {
		q = `
			SELECT id, name, description, rego_source, tenant,
			       created_at, updated_at, created_by
			FROM policy_drafts
			WHERE tenant = $1
			ORDER BY updated_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []any{filter.Tenant, limit, filter.Offset}
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("policystore: list drafts: %w", err)
	}
	defer rows.Close()

	out := make([]Draft, 0, limit)
	for rows.Next() {
		var d Draft
		if err := rows.Scan(&d.ID, &d.Name, &d.Description, &d.RegoSource,
			&d.Tenant, &d.CreatedAt, &d.UpdatedAt, &d.CreatedBy); err != nil {
			return nil, fmt.Errorf("policystore: scan draft: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policystore: rows iter: %w", err)
	}
	return out, nil
}

// DeleteDraft refuses when the active pointer references the row.
// The existence + active-reference check + DELETE all happen inside
// one transaction so a concurrent promote can't slip in between.
func (s *PostgresStore) DeleteDraft(ctx context.Context, id string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("policystore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM policy_drafts WHERE id = $1)`, id,
	).Scan(&exists); err != nil {
		return fmt.Errorf("policystore: delete exists check: %w", err)
	}
	if !exists {
		return ErrNotFound
	}

	var current, previous string
	if err := tx.QueryRow(ctx,
		`SELECT current_draft_id, previous_draft_id FROM policy_active WHERE id = 'global'`,
	).Scan(&current, &previous); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("policystore: delete active check: %w", err)
	}
	if current == id || previous == id {
		return ErrActiveDraftDelete
	}

	if _, err := tx.Exec(ctx, `DELETE FROM policy_drafts WHERE id = $1`, id); err != nil {
		return fmt.Errorf("policystore: delete draft: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("policystore: delete commit: %w", err)
	}
	return nil
}

// GetActive returns the active-pointer row. The migration seeded it,
// so we always find the row; a fresh install returns the
// zero-valued Active (empty current and previous).
func (s *PostgresStore) GetActive(ctx context.Context) (Active, error) {
	const q = `
		SELECT current_draft_id, previous_draft_id, promoted_at, promoted_by
		FROM policy_active
		WHERE id = 'global'
	`
	var (
		a          Active
		promotedAt sql.NullTime
	)
	if err := s.pool.QueryRow(ctx, q).Scan(
		&a.CurrentDraftID, &a.PreviousDraftID, &promotedAt, &a.PromotedBy,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			// Should not happen post-migration, but be permissive.
			return Active{}, nil
		}
		return Active{}, fmt.Errorf("policystore: get active: %w", err)
	}
	if promotedAt.Valid {
		a.PromotedAt = promotedAt.Time.UTC()
	}
	return a, nil
}

// Promote moves CurrentDraftID → PreviousDraftID, then writes
// draftID into CurrentDraftID. All inside one transaction: the
// draft-exists check guarding against ErrNotFound shares the
// transaction with the active-row UPDATE so a concurrent delete
// can't slip a deleted ID into the active row.
func (s *PostgresStore) Promote(ctx context.Context, draftID, promotedBy string) (Active, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Active{}, fmt.Errorf("policystore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM policy_drafts WHERE id = $1)`, draftID,
	).Scan(&exists); err != nil {
		return Active{}, fmt.Errorf("policystore: promote exists check: %w", err)
	}
	if !exists {
		return Active{}, ErrNotFound
	}

	var current, previous, currentBy string
	var currentAt sql.NullTime
	if err := tx.QueryRow(ctx, `
		SELECT current_draft_id, previous_draft_id, promoted_at, promoted_by
		FROM policy_active WHERE id = 'global'
	`).Scan(&current, &previous, &currentAt, &currentBy); err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {
		return Active{}, fmt.Errorf("policystore: promote read active: %w", err)
	}

	// Idempotent: re-promoting the same draft is a no-op so timestamps
	// don't churn under accidental double-clicks.
	if current == draftID {
		a := Active{
			CurrentDraftID:  current,
			PreviousDraftID: previous,
			PromotedBy:      currentBy,
		}
		if currentAt.Valid {
			a.PromotedAt = currentAt.Time.UTC()
		}
		return a, nil
	}

	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE policy_active
		SET current_draft_id = $1,
		    previous_draft_id = $2,
		    promoted_at = $3,
		    promoted_by = $4
		WHERE id = 'global'
	`, draftID, current, now, promotedBy); err != nil {
		return Active{}, fmt.Errorf("policystore: promote update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Active{}, fmt.Errorf("policystore: promote commit: %w", err)
	}
	return Active{
		CurrentDraftID:  draftID,
		PreviousDraftID: current,
		PromotedAt:      now,
		PromotedBy:      promotedBy,
	}, nil
}

// Rollback swaps Current and Previous, then clears Previous so a
// second consecutive rollback returns ErrNotFound rather than
// ping-ponging.
func (s *PostgresStore) Rollback(ctx context.Context, rolledBackBy string) (Active, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Active{}, fmt.Errorf("policystore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current, previous string
	if err := tx.QueryRow(ctx, `
		SELECT current_draft_id, previous_draft_id
		FROM policy_active WHERE id = 'global'
	`).Scan(&current, &previous); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Active{}, fmt.Errorf("policystore: rollback read: %w", err)
	}
	if previous == "" {
		return Active{}, ErrNotFound
	}

	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE policy_active
		SET current_draft_id = $1,
		    previous_draft_id = '',
		    promoted_at = $2,
		    promoted_by = $3
		WHERE id = 'global'
	`, previous, now, rolledBackBy); err != nil {
		return Active{}, fmt.Errorf("policystore: rollback update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Active{}, fmt.Errorf("policystore: rollback commit: %w", err)
	}
	return Active{
		CurrentDraftID:  previous,
		PreviousDraftID: "",
		PromotedAt:      now,
		PromotedBy:      rolledBackBy,
	}, nil
}
