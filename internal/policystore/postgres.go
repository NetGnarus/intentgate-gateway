package policystore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// notifyChannel is the Postgres LISTEN/NOTIFY channel used to
// broadcast active-pointer changes across gateway replicas. Each
// Promote and Rollback emits NOTIFY <channel>, '<draft_id>' inside
// its existing transaction so the payload is committed atomically
// with the pointer write.
const notifyChannel = "intentgate_policy_active_changed"

// pollFallbackInterval is how often the listener goroutine
// re-reads the active row as a belt-and-suspenders check during
// reconnect windows. 5 seconds is operator-noticeable (worst case)
// without being chatty against Postgres on idle clusters.
const pollFallbackInterval = 5 * time.Second

// PostgresStore is a durable, multi-replica-safe policy-draft store.
//
// Promote and Rollback are transactional: existence check on the
// referenced draft and the update of policy_active happen inside a
// single SERIALIZABLE-equivalent transaction, so a concurrent
// DeleteDraft can't slip between the check and the write.
//
// # Cross-replica refresh
//
// Each Promote and Rollback emits NOTIFY [notifyChannel] inside its
// transaction. A background goroutine started by NewPostgresStore
// LISTENs on the same channel and fans incoming notifications out
// to every Watch subscriber. A polling fallback (every
// [pollFallbackInterval]) re-reads the active row so a brief
// connection drop can't leave a replica running stale policy
// indefinitely. Together they give same-rollout multi-replica
// gateways near-real-time agreement on which draft is live.
type PostgresStore struct {
	pool   *pgxpool.Pool
	logger *slog.Logger

	mu       sync.Mutex
	watchers []chan Active

	listenerCancel context.CancelFunc
	listenerDone   chan struct{}
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

	listenCtx, listenCancel := context.WithCancel(context.Background())
	s := &PostgresStore{
		pool:           pool,
		logger:         slog.Default(),
		listenerCancel: listenCancel,
		listenerDone:   make(chan struct{}),
	}
	go s.runListener(listenCtx)
	return s, nil
}

// Close stops the listener goroutine, closes outstanding Watch
// channels, and releases the pool. Safe to call multiple times.
func (s *PostgresStore) Close() error {
	if s.listenerCancel != nil {
		s.listenerCancel()
		<-s.listenerDone
		s.listenerCancel = nil
	}
	s.mu.Lock()
	for _, ch := range s.watchers {
		close(ch)
	}
	s.watchers = nil
	s.mu.Unlock()
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// Watch returns a buffered channel that receives an [Active] value
// every time the policy_active row changes — either via a NOTIFY
// from another replica or via the polling fallback. The channel
// closes when ctx is cancelled or the store is closed.
func (s *PostgresStore) Watch(ctx context.Context) (<-chan Active, error) {
	ch := make(chan Active, 4)
	s.mu.Lock()
	s.watchers = append(s.watchers, ch)
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.unsubscribe(ch)
	}()
	return ch, nil
}

func (s *PostgresStore) unsubscribe(target chan Active) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ch := range s.watchers {
		if ch == target {
			s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
			close(ch)
			return
		}
	}
}

// fanOut delivers an Active value to every subscriber. Drops on
// full buffer so one slow consumer can't stall the listener.
func (s *PostgresStore) fanOut(a Active) {
	s.mu.Lock()
	subs := make([]chan Active, len(s.watchers))
	copy(subs, s.watchers)
	s.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- a:
		default:
		}
	}
}

// runListener is the long-lived goroutine that LISTENs on the
// notify channel and polls every [pollFallbackInterval] as a
// reconnect-window safety net. Reconnects on connection drop with
// a small backoff. Returns when ctx is cancelled (Close).
func (s *PostgresStore) runListener(ctx context.Context) {
	defer close(s.listenerDone)
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.listenerSession(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("policystore: listener session error; reconnecting",
				"err", err)
			// Brief backoff before reconnecting so we don't tight-loop
			// against a misconfigured Postgres.
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}

// listenerSession runs one acquire→LISTEN→wait-loop. On any error
// from the underlying pgconn (other than the poll-timeout we
// orchestrate ourselves) it returns to runListener, which decides
// whether to reconnect. Returns when ctx (the parent / shutdown
// context) is cancelled too.
func (s *PostgresStore) listenerSession(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Track the last fan-out's CurrentDraftID so the polling
	// fallback doesn't broadcast on every poll — only when the
	// active row actually changed since last seen. The listener
	// path emits unconditionally because by definition a NOTIFY
	// fired only because something committed.
	lastID := ""

	for {
		// We want WaitForNotification to return either when a real
		// NOTIFY arrives OR when our polling interval lapses, so we
		// derive a child ctx with that interval as a deadline. On
		// DeadlineExceeded we do the poll; on a real notification
		// we fan-out the fresh Active; on the parent ctx being
		// cancelled we bail out cleanly.
		waitCtx, cancelWait := context.WithTimeout(ctx, pollFallbackInterval)
		n, err := conn.Conn().WaitForNotification(waitCtx)
		cancelWait()

		switch {
		case err == nil:
			// Real NOTIFY. Read active and fan-out unconditionally
			// — a notify-without-change is impossible by construction
			// (Promote/Rollback are the only emitters and both run
			// inside their own pointer-mutating transactions).
			_ = n // payload carries the draft id, but we re-read for safety
			active, getErr := s.GetActive(ctx)
			if getErr != nil {
				s.logger.Warn("policystore: GetActive after NOTIFY failed",
					"err", getErr)
				continue
			}
			lastID = active.CurrentDraftID
			s.fanOut(active)

		case errors.Is(err, context.DeadlineExceeded):
			// Polling fallback fires. Only emit if the active row
			// looks different from what we last delivered — keeps
			// the every-5s tick from spamming the bus on an idle
			// cluster.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			active, getErr := s.GetActive(ctx)
			if getErr != nil {
				s.logger.Warn("policystore: polling GetActive failed",
					"err", getErr)
				continue
			}
			if active.CurrentDraftID != lastID {
				lastID = active.CurrentDraftID
				s.fanOut(active)
			}

		case errors.Is(err, context.Canceled):
			// Parent ctx cancelled (Close). Propagate.
			return err

		default:
			// pgconn-level error — connection dropped, server
			// rebooted, network blip. Return so runListener
			// reconnects.
			return fmt.Errorf("wait for notification: %w", err)
		}
	}
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
	// Broadcast to every replica's listener BEFORE commit so the
	// NOTIFY rides in the same transaction as the pointer write —
	// either both land or both roll back. Postgres queues the
	// notification until commit, so subscribers only see it after
	// the row update is visible. Payload is the new draft id so a
	// future listener that wants to skip the GetActive round-trip
	// could read it directly. pg_notify is the parameterized form;
	// the bare NOTIFY statement doesn't accept placeholders.
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel, draftID); err != nil {
		return Active{}, fmt.Errorf("policystore: promote notify: %w", err)
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
	// Same NOTIFY hook as Promote — the listener handles both kinds
	// of pointer change identically (re-fetch + fan-out).
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel, previous); err != nil {
		return Active{}, fmt.Errorf("policystore: rollback notify: %w", err)
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
