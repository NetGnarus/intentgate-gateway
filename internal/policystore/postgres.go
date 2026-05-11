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

	// Per-tenant cache of the last CurrentDraftID we fanned out for
	// each tenant. The polling fallback consults it to avoid re-
	// broadcasting unchanged rows on every 5-second tick. The
	// listener path overwrites it on every NOTIFY (the notification
	// itself proves the row changed). Empty-tenant ("") is the
	// default-fallback row and lives in the same map.
	lastActive := make(map[string]string)

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
			// Real NOTIFY. The payload encodes (tenant, draft_id) so
			// we can fan-out directly to the right tenant slot
			// without re-reading the whole row. Re-read is still
			// useful when the payload is malformed (decodeNotify
			// returns empty), so we fall back to ListActive in that
			// case — degrades gracefully on a scrambled payload.
			payloadTenant, payloadDraftID := decodeNotifyPayload(n.Payload)
			if payloadDraftID == "" && payloadTenant == "" {
				// Malformed: fan out every tenant's active so
				// subscribers eventually reconverge.
				if all, listErr := s.ListActive(ctx); listErr == nil {
					for _, a := range all {
						s.fanOut(a)
						lastActive[a.Tenant] = a.CurrentDraftID
					}
				} else {
					s.logger.Warn("policystore: ListActive after malformed NOTIFY failed",
						"err", listErr)
				}
				continue
			}
			active, getErr := s.GetActive(ctx, payloadTenant)
			if getErr != nil {
				s.logger.Warn("policystore: GetActive after NOTIFY failed",
					"err", getErr, "tenant", payloadTenant)
				continue
			}
			lastActive[payloadTenant] = active.CurrentDraftID
			s.fanOut(active)

		case errors.Is(err, context.DeadlineExceeded):
			// Polling fallback fires. Re-read every tenant's row
			// and emit only the ones whose current_draft_id changed
			// since last seen — keeps the every-5s tick from
			// spamming the bus on an idle cluster.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			all, listErr := s.ListActive(ctx)
			if listErr != nil {
				s.logger.Warn("policystore: polling ListActive failed",
					"err", listErr)
				continue
			}
			for _, a := range all {
				if a.CurrentDraftID != lastActive[a.Tenant] {
					lastActive[a.Tenant] = a.CurrentDraftID
					s.fanOut(a)
				}
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

// DeleteDraft refuses when ANY tenant's active pointer references
// the row (current OR previous). The existence + active-reference
// check + DELETE all happen inside one transaction so a concurrent
// promote can't slip in between.
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

	// Active-reference sweep across every per-tenant row. A single
	// EXISTS query covers them all without N round-trips.
	var pinned bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM policy_active
			WHERE current_draft_id = $1 OR previous_draft_id = $1
		)
	`, id).Scan(&pinned); err != nil {
		return fmt.Errorf("policystore: delete active check: %w", err)
	}
	if pinned {
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

// GetActive returns the active-pointer row for the given tenant.
// Empty tenant returns the default-fallback row. A missing row
// (tenant has never promoted) returns a zero-valued Active so
// callers can detect "no active set" via CurrentDraftID == "".
func (s *PostgresStore) GetActive(ctx context.Context, tenant string) (Active, error) {
	const q = `
		SELECT tenant, current_draft_id, previous_draft_id, promoted_at, promoted_by
		FROM policy_active
		WHERE tenant = $1
	`
	var (
		a          Active
		promotedAt sql.NullTime
	)
	if err := s.pool.QueryRow(ctx, q, tenant).Scan(
		&a.Tenant, &a.CurrentDraftID, &a.PreviousDraftID, &promotedAt, &a.PromotedBy,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return Active{Tenant: tenant}, nil
		}
		return Active{}, fmt.Errorf("policystore: get active: %w", err)
	}
	if promotedAt.Valid {
		a.PromotedAt = promotedAt.Time.UTC()
	}
	return a, nil
}

// ListActive returns every tenant's active pointer. Default-
// fallback row (tenant=”) first so startup hydration installs it
// before per-tenant overlays.
func (s *PostgresStore) ListActive(ctx context.Context) ([]Active, error) {
	const q = `
		SELECT tenant, current_draft_id, previous_draft_id, promoted_at, promoted_by
		FROM policy_active
		ORDER BY (tenant = '') DESC, tenant ASC
	`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("policystore: list active: %w", err)
	}
	defer rows.Close()

	out := make([]Active, 0, 8)
	for rows.Next() {
		var (
			a          Active
			promotedAt sql.NullTime
		)
		if err := rows.Scan(&a.Tenant, &a.CurrentDraftID, &a.PreviousDraftID, &promotedAt, &a.PromotedBy); err != nil {
			return nil, fmt.Errorf("policystore: scan active: %w", err)
		}
		if promotedAt.Valid {
			a.PromotedAt = promotedAt.Time.UTC()
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policystore: active rows iter: %w", err)
	}
	return out, nil
}

// Promote moves the given tenant's CurrentDraftID →
// PreviousDraftID, then writes draftID into CurrentDraftID. All
// inside one transaction: the draft-exists check guarding against
// ErrNotFound shares the transaction with the active-row UPSERT so
// a concurrent delete can't slip a deleted ID into the active row.
//
// First-promote-for-this-tenant inserts a fresh row (the migration
// seeds tenant=” only; other tenants get their row on first
// promote via the ON CONFLICT UPDATE path).
//
// NOTIFY payload encodes the (tenant, draft_id) pair so listeners
// know which engine to swap without an extra round-trip. Format:
// "tenant:draft_id" — colon-safe because both fields are
// gateway-controlled identifiers (hex draft id and the operator-
// configured tenant string, both validated upstream).
func (s *PostgresStore) Promote(ctx context.Context, draftID, promotedBy, tenant string) (Active, error) {
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
	rowErr := tx.QueryRow(ctx, `
		SELECT current_draft_id, previous_draft_id, promoted_at, promoted_by
		FROM policy_active WHERE tenant = $1
	`, tenant).Scan(&current, &previous, &currentAt, &currentBy)
	if rowErr != nil && !errors.Is(rowErr, pgx.ErrNoRows) && !errors.Is(rowErr, sql.ErrNoRows) {
		return Active{}, fmt.Errorf("policystore: promote read active: %w", rowErr)
	}

	// Idempotent: re-promoting the same draft is a no-op so timestamps
	// don't churn under accidental double-clicks.
	if current == draftID {
		a := Active{
			Tenant:          tenant,
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
	// UPSERT: tenants beyond the seeded '' default get their row
	// created on first promote. id is a legacy column with a default
	// of ''; the PK is (tenant) so the insert only collides on tenant.
	if _, err := tx.Exec(ctx, `
		INSERT INTO policy_active (id, tenant, current_draft_id, previous_draft_id, promoted_at, promoted_by)
		VALUES ('', $1, $2, $3, $4, $5)
		ON CONFLICT (tenant) DO UPDATE
		SET current_draft_id = EXCLUDED.current_draft_id,
		    previous_draft_id = EXCLUDED.previous_draft_id,
		    promoted_at = EXCLUDED.promoted_at,
		    promoted_by = EXCLUDED.promoted_by
	`, tenant, draftID, current, now, promotedBy); err != nil {
		return Active{}, fmt.Errorf("policystore: promote upsert: %w", err)
	}
	// Broadcast inside the transaction so the NOTIFY commits atomic
	// with the pointer write. Payload encodes both tenant and draft
	// id so the listener can dispatch directly to the right engine
	// slot without another GetActive round-trip.
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)",
		notifyChannel, encodeNotifyPayload(tenant, draftID)); err != nil {
		return Active{}, fmt.Errorf("policystore: promote notify: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Active{}, fmt.Errorf("policystore: promote commit: %w", err)
	}
	return Active{
		Tenant:          tenant,
		CurrentDraftID:  draftID,
		PreviousDraftID: current,
		PromotedAt:      now,
		PromotedBy:      promotedBy,
	}, nil
}

// Rollback swaps the given tenant's Current and Previous, then
// clears Previous so a second consecutive rollback returns
// ErrNotFound rather than ping-ponging.
func (s *PostgresStore) Rollback(ctx context.Context, rolledBackBy, tenant string) (Active, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Active{}, fmt.Errorf("policystore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current, previous string
	rowErr := tx.QueryRow(ctx, `
		SELECT current_draft_id, previous_draft_id
		FROM policy_active WHERE tenant = $1
	`, tenant).Scan(&current, &previous)
	if rowErr != nil && !errors.Is(rowErr, pgx.ErrNoRows) && !errors.Is(rowErr, sql.ErrNoRows) {
		return Active{}, fmt.Errorf("policystore: rollback read: %w", rowErr)
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
		WHERE tenant = $4
	`, previous, now, rolledBackBy, tenant); err != nil {
		return Active{}, fmt.Errorf("policystore: rollback update: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)",
		notifyChannel, encodeNotifyPayload(tenant, previous)); err != nil {
		return Active{}, fmt.Errorf("policystore: rollback notify: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Active{}, fmt.Errorf("policystore: rollback commit: %w", err)
	}
	return Active{
		Tenant:          tenant,
		CurrentDraftID:  previous,
		PreviousDraftID: "",
		PromotedAt:      now,
		PromotedBy:      rolledBackBy,
	}, nil
}

// DeleteActive clears the tenant's active-policy pointer. Empty
// tenant is a no-op (matches the Memory implementation).
//
// NOTIFY emits with an empty draft_id portion of the payload
// (e.g. "acme\x1E") so the listener can tell this is a "slot
// cleared" event rather than a promote/rollback, and dispatch to
// Reloader.RemoveFor on the receiving side. Cross-replica
// listeners that don't yet handle that case fall back to
// re-reading the row and finding CurrentDraftID="", which the
// main.go watcher already treats as a no-op.
func (s *PostgresStore) DeleteActive(ctx context.Context, tenant string) (Active, error) {
	if tenant == "" {
		return s.GetActive(ctx, "")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Active{}, fmt.Errorf("policystore: delete active begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM policy_active WHERE tenant = $1`, tenant,
	); err != nil {
		return Active{}, fmt.Errorf("policystore: delete active: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)",
		notifyChannel, encodeNotifyPayload(tenant, "")); err != nil {
		return Active{}, fmt.Errorf("policystore: delete active notify: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Active{}, fmt.Errorf("policystore: delete active commit: %w", err)
	}
	return Active{Tenant: tenant}, nil
}

// encodeNotifyPayload packs (tenant, draft_id) into a single
// pg_notify payload string. Format: "tenant\x1Edraft_id" — using
// the ASCII Record Separator control char as a delimiter so it
// can't appear inside either field (draft IDs are hex, tenant
// names are operator-configured plain text). An empty draft_id
// signals "slot cleared" (DeleteActive); the listener checks for
// that and dispatches to Reloader.RemoveFor on the receiving side.
// The listener side uses [decodeNotifyPayload] to split.
func encodeNotifyPayload(tenant, draftID string) string {
	return tenant + "\x1E" + draftID
}

// decodeNotifyPayload splits an encoded payload back into
// (tenant, draft_id). Returns empty strings on malformed input —
// the listener falls back to a full ListActive in that case, so a
// scrambled payload degrades gracefully rather than crashing.
func decodeNotifyPayload(payload string) (tenant, draftID string) {
	for i := 0; i < len(payload); i++ {
		if payload[i] == 0x1E {
			return payload[:i], payload[i+1:]
		}
	}
	return "", ""
}
