package approvals

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// PostgresStore is the durable, multi-replica-safe approvals queue.
//
// # LISTEN/NOTIFY for cross-replica wakeups
//
// A Wait blocked on replica A must be woken when Decide runs on
// replica B. Postgres' LISTEN/NOTIFY gives us exactly that: each
// replica LISTENs on the channel `intentgate_approvals`, and Decide
// emits NOTIFY <pending_id>. A background goroutine reads
// notifications and signals the per-id wait channel.
//
// Replica restart drops in-flight LISTEN sessions; a Wait that
// outlives that restart becomes a polled Wait via the database
// fallback (a 1-second poll while still under the caller's deadline).
// Acceptable for v1 — the LISTEN path covers the common case and
// the poll keeps correctness on the cold path.
type PostgresStore struct {
	pool *pgxpool.Pool

	mu    sync.Mutex
	waits map[string]chan struct{}

	// listenerCancel stops the background LISTEN goroutine on Close.
	listenerCancel context.CancelFunc
	listenerDone   chan struct{}
}

const notifyChannel = "intentgate_approvals"

// NewPostgresStore connects, pings, applies the migration, and
// starts the LISTEN goroutine.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("approvals: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("approvals: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 10
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("approvals: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("approvals: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("approvals: migrate: %w", err)
	}

	listenCtx, listenCancel := context.WithCancel(context.Background())
	s := &PostgresStore{
		pool:           pool,
		waits:          make(map[string]chan struct{}),
		listenerCancel: listenCancel,
		listenerDone:   make(chan struct{}),
	}
	go s.runListener(listenCtx)
	return s, nil
}

// Close stops the listener and releases the pool.
func (s *PostgresStore) Close() error {
	if s.listenerCancel != nil {
		s.listenerCancel()
		<-s.listenerDone
	}
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// runListener subscribes to NOTIFY <pending_id> and wakes any
// per-id wait channel. Reconnects on connection drop with a small
// backoff. Terminates when ctx is cancelled (Close).
func (s *PostgresStore) runListener(ctx context.Context) {
	defer close(s.listenerDone)
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := s.pool.Acquire(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Second)
			continue
		}
		if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
			conn.Release()
			time.Sleep(time.Second)
			continue
		}
		for {
			n, err := conn.Conn().WaitForNotification(ctx)
			if err != nil {
				break
			}
			s.mu.Lock()
			if ch, ok := s.waits[n.Payload]; ok {
				delete(s.waits, n.Payload)
				close(ch)
			}
			s.mu.Unlock()
		}
		conn.Release()
	}
}

// Enqueue inserts the row and returns it.
func (s *PostgresStore) Enqueue(ctx context.Context, req PendingRequest) (PendingRequest, error) {
	if req.PendingID == "" {
		id, err := NewPendingID()
		if err != nil {
			return PendingRequest{}, err
		}
		req.PendingID = id
	}
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now().UTC()
	}
	req.Status = StatusPending

	var argsJSON []byte
	if len(req.Args) > 0 {
		var err error
		argsJSON, err = json.Marshal(req.Args)
		if err != nil {
			return PendingRequest{}, fmt.Errorf("approvals: marshal args: %w", err)
		}
	}

	const q = `
		INSERT INTO pending_approvals (
			pending_id, capability_token_id, root_capability_token_id,
			agent_id, tool, args, intent_summary, reason,
			status, created_at, tenant, requires_step_up
		) VALUES (
			$1, $2, $3,
			$4, $5, $6, $7, $8,
			'pending', $9, $10, $11
		)
	`
	if _, err := s.pool.Exec(ctx, q,
		req.PendingID, nullableString(req.CapabilityTokenID), nullableString(req.RootCapabilityTokenID),
		req.AgentID, req.Tool, argsJSON, req.IntentSummary, req.Reason,
		req.CreatedAt, nullableString(req.Tenant), req.RequiresStepUp,
	); err != nil {
		return PendingRequest{}, fmt.Errorf("approvals: insert: %w", err)
	}
	return req, nil
}

// Wait blocks until status leaves pending OR ctx is cancelled.
// Combines LISTEN/NOTIFY (fast path) with a 1s polling fallback
// (cold path — listener reconnect window).
func (s *PostgresStore) Wait(ctx context.Context, pendingID string) (PendingRequest, error) {
	// Register the wait channel BEFORE the first read so a Decide
	// that races us doesn't slip past.
	s.mu.Lock()
	ch, ok := s.waits[pendingID]
	if !ok {
		ch = make(chan struct{})
		s.waits[pendingID] = ch
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if existing, ok := s.waits[pendingID]; ok && existing == ch {
			delete(s.waits, pendingID)
		}
		s.mu.Unlock()
	}()

	// First synchronous Get: another replica may have decided
	// before our Wait registered. Saves a round trip on the cold
	// path.
	got, err := s.Get(ctx, pendingID)
	if err != nil {
		return PendingRequest{}, err
	}
	if got.Status != StatusPending {
		return got, nil
	}

	poll := time.NewTicker(time.Second)
	defer poll.Stop()

	for {
		select {
		case <-ch:
			// Listener fired. Read the final state.
			final, err := s.Get(ctx, pendingID)
			return final, err
		case <-poll.C:
			// Polling fallback in case the listener is reconnecting.
			cur, err := s.Get(ctx, pendingID)
			if err != nil {
				return PendingRequest{}, err
			}
			if cur.Status != StatusPending {
				return cur, nil
			}
		case <-ctx.Done():
			// Timeout. Try to mark the row as timed-out atomically.
			final, terr := s.markTimeout(context.Background(), pendingID)
			if terr != nil {
				return PendingRequest{}, terr
			}
			return final, nil
		}
	}
}

// markTimeout flips a still-pending row to status=timeout. If a
// concurrent Decide raced us, we return whatever the row's final
// state actually is.
func (s *PostgresStore) markTimeout(ctx context.Context, pendingID string) (PendingRequest, error) {
	const q = `
		UPDATE pending_approvals
		SET status = 'timeout', decided_at = NOW()
		WHERE pending_id = $1 AND status = 'pending'
	`
	if _, err := s.pool.Exec(ctx, q, pendingID); err != nil {
		return PendingRequest{}, fmt.Errorf("approvals: mark timeout: %w", err)
	}
	return s.Get(ctx, pendingID)
}

// Decide records an approve/reject and emits NOTIFY so any waiting
// gateway replica wakes up.
func (s *PostgresStore) Decide(ctx context.Context, pendingID string, dec Decision) (PendingRequest, error) {
	if dec.Status != StatusApproved && dec.Status != StatusRejected {
		return PendingRequest{}, errors.New("approvals: decision must be approved or rejected")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PendingRequest{}, fmt.Errorf("approvals: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const update = `
		UPDATE pending_approvals
		SET status = $2, decided_at = NOW(), decided_by = $3, decide_note = $4
		WHERE pending_id = $1 AND status = 'pending'
		RETURNING pending_id
	`
	var ignored string
	row := tx.QueryRow(ctx, update, pendingID, string(dec.Status), dec.DecidedBy, dec.Note)
	if err := row.Scan(&ignored); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Either not found OR already decided. Read to find out.
			rb := tx.Rollback(ctx)
			_ = rb
			cur, gerr := s.Get(ctx, pendingID)
			if errors.Is(gerr, ErrNotFound) {
				return PendingRequest{}, ErrNotFound
			}
			if gerr != nil {
				return PendingRequest{}, gerr
			}
			return cur, ErrAlreadyDecided
		}
		return PendingRequest{}, fmt.Errorf("approvals: update: %w", err)
	}

	if _, err := tx.Exec(ctx, "NOTIFY "+notifyChannel+", '"+pendingID+"'"); err != nil {
		return PendingRequest{}, fmt.Errorf("approvals: notify: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PendingRequest{}, fmt.Errorf("approvals: commit: %w", err)
	}

	return s.Get(ctx, pendingID)
}

// Get reads a single row.
func (s *PostgresStore) Get(ctx context.Context, pendingID string) (PendingRequest, error) {
	const q = `
		SELECT pending_id, capability_token_id, root_capability_token_id,
			agent_id, tool, args, intent_summary, reason,
			status, created_at, decided_at, decided_by, decide_note, tenant,
			requires_step_up
		FROM pending_approvals
		WHERE pending_id = $1
	`
	var (
		row     PendingRequest
		captok  *string
		roottok *string
		args    []byte
		decAt   *time.Time
		status  string
		tenant  *string
	)
	err := s.pool.QueryRow(ctx, q, pendingID).Scan(
		&row.PendingID, &captok, &roottok,
		&row.AgentID, &row.Tool, &args, &row.IntentSummary, &row.Reason,
		&status, &row.CreatedAt, &decAt, &row.DecidedBy, &row.DecideNote, &tenant,
		&row.RequiresStepUp,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingRequest{}, ErrNotFound
	}
	if err != nil {
		return PendingRequest{}, fmt.Errorf("approvals: get: %w", err)
	}
	if captok != nil {
		row.CapabilityTokenID = *captok
	}
	if roottok != nil {
		row.RootCapabilityTokenID = *roottok
	}
	if tenant != nil {
		row.Tenant = *tenant
	}
	row.Status = Status(status)
	row.DecidedAt = decAt
	if len(args) > 0 {
		_ = json.Unmarshal(args, &row.Args)
	}
	return row, nil
}

// List returns rows matching the filter.
func (s *PostgresStore) List(ctx context.Context, f ListFilter) ([]PendingRequest, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	q := `
		SELECT pending_id, capability_token_id, root_capability_token_id,
			agent_id, tool, args, intent_summary, reason,
			status, created_at, decided_at, decided_by, decide_note, tenant,
			requires_step_up
		FROM pending_approvals
	`
	args := []any{}
	clauses := []string{}
	if f.Status != "" {
		args = append(args, string(f.Status))
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if f.Tenant != "" {
		args = append(args, f.Tenant)
		clauses = append(clauses, fmt.Sprintf("tenant = $%d", len(args)))
	}
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("approvals: list: %w", err)
	}
	defer rows.Close()

	out := make([]PendingRequest, 0, limit)
	for rows.Next() {
		var (
			row     PendingRequest
			captok  *string
			roottok *string
			rawArgs []byte
			decAt   *time.Time
			status  string
			tenant  *string
		)
		if err := rows.Scan(
			&row.PendingID, &captok, &roottok,
			&row.AgentID, &row.Tool, &rawArgs, &row.IntentSummary, &row.Reason,
			&status, &row.CreatedAt, &decAt, &row.DecidedBy, &row.DecideNote, &tenant,
			&row.RequiresStepUp,
		); err != nil {
			return nil, fmt.Errorf("approvals: scan: %w", err)
		}
		if captok != nil {
			row.CapabilityTokenID = *captok
		}
		if roottok != nil {
			row.RootCapabilityTokenID = *roottok
		}
		if tenant != nil {
			row.Tenant = *tenant
		}
		row.Status = Status(status)
		row.DecidedAt = decAt
		if len(rawArgs) > 0 {
			_ = json.Unmarshal(rawArgs, &row.Args)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("approvals: rows iter: %w", err)
	}
	return out, nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
