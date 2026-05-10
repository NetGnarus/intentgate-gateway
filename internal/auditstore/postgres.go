package auditstore

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is the migration applied at startup. Idempotent.
//
//go:embed schema.sql
var schemaSQL string

// PostgresStore is a durable, queryable, multi-replica-safe audit-event
// store backed by Postgres.
//
// The same Postgres instance the [revocation] package uses is reused —
// one DSN, one pool per store. Operators wanting a separate database
// for audit can simply point a second URL at a different host; the
// stores are independent.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects, pings, applies the embedded migration,
// and returns a ready-to-use Store.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("auditstore: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("auditstore: parse DSN: %w", err)
	}
	// A modestly larger pool than revocation: inserts are write-heavy
	// (one per request) and the async emitter may flush bursts.
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 20
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("auditstore: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("auditstore: ping: %w", err)
	}

	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("auditstore: migrate: %w", err)
	}

	return &PostgresStore{pool: pool}, nil
}

// Close releases the connection pool. Safe to call multiple times.
func (s *PostgresStore) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// Insert adds one event. The audit.Event timestamp is RFC3339Nano text
// in JSON; we parse it to TIMESTAMPTZ here so SQL queries can range
// over it without text-vs-timestamp coercion.
func (s *PostgresStore) Insert(ctx context.Context, e audit.Event) error {
	ts, err := parseEventTime(e.Timestamp)
	if err != nil {
		// An audit event with an unparseable timestamp shouldn't happen
		// (NewEvent always sets RFC3339Nano UTC) but if it does we use
		// "now" rather than refusing to record the event. Audit
		// emission is meant to be best-effort.
		ts = time.Now().UTC()
	}

	var argKeysJSON []byte
	if len(e.ArgKeys) > 0 {
		argKeysJSON, err = json.Marshal(e.ArgKeys)
		if err != nil {
			return fmt.Errorf("auditstore: marshal arg_keys: %w", err)
		}
	}

	const q = `
		INSERT INTO audit_events (
			ts, event_name, schema_version,
			decision, check_stage, reason,
			agent_id, session_id,
			tool, arg_keys,
			capability_token_id, intent_summary,
			latency_ms, remote_ip, upstream_status
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8,
			$9, $10,
			$11, $12,
			$13, $14, $15
		)
	`
	if _, err := s.pool.Exec(ctx, q,
		ts, defaultStr(e.EventName, "intentgate.tool_call"), defaultStr(e.SchemaVersion, "1"),
		string(e.Decision), string(e.Check), e.Reason,
		e.AgentID, e.SessionID,
		e.Tool, argKeysJSON,
		e.CapabilityTokenID, e.IntentSummary,
		e.LatencyMS, e.RemoteIP, e.UpstreamStatus,
	); err != nil {
		return fmt.Errorf("auditstore: insert: %w", err)
	}
	return nil
}

// Query returns matching events most-recent first.
func (s *PostgresStore) Query(ctx context.Context, f QueryFilter) ([]audit.Event, error) {
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

	where, args := buildWhere(f)
	q := `
		SELECT ts, event_name, schema_version,
			decision, check_stage, reason,
			agent_id, session_id,
			tool, arg_keys,
			capability_token_id, intent_summary,
			latency_ms, remote_ip, upstream_status
		FROM audit_events
	` + where + `
		ORDER BY ts DESC
		LIMIT ` + placeholder(len(args)+1) + ` OFFSET ` + placeholder(len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("auditstore: query: %w", err)
	}
	defer rows.Close()

	out := make([]audit.Event, 0, limit)
	for rows.Next() {
		var (
			ts          time.Time
			argKeysJSON []byte
			ev          audit.Event
			decision    string
			check       string
		)
		if err := rows.Scan(
			&ts, &ev.EventName, &ev.SchemaVersion,
			&decision, &check, &ev.Reason,
			&ev.AgentID, &ev.SessionID,
			&ev.Tool, &argKeysJSON,
			&ev.CapabilityTokenID, &ev.IntentSummary,
			&ev.LatencyMS, &ev.RemoteIP, &ev.UpstreamStatus,
		); err != nil {
			return nil, fmt.Errorf("auditstore: scan: %w", err)
		}
		ev.Timestamp = ts.UTC().Format(time.RFC3339Nano)
		ev.Decision = audit.Decision(decision)
		ev.Check = audit.Check(check)
		if len(argKeysJSON) > 0 {
			_ = json.Unmarshal(argKeysJSON, &ev.ArgKeys)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auditstore: rows iter: %w", err)
	}
	return out, nil
}

// Count returns the number of events matching the filter (ignoring
// limit / offset). Used by paginated UIs that want a total page count.
func (s *PostgresStore) Count(ctx context.Context, f QueryFilter) (int64, error) {
	where, args := buildWhere(f)
	q := `SELECT COUNT(*) FROM audit_events` + where
	var n int64
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("auditstore: count: %w", err)
	}
	return n, nil
}

// buildWhere assembles the WHERE clause + args for a filter. Returns
// the empty string when no filter applies.
func buildWhere(f QueryFilter) (string, []any) {
	var clauses []string
	var args []any
	if !f.From.IsZero() {
		args = append(args, f.From)
		clauses = append(clauses, "ts >= "+placeholder(len(args)))
	}
	if !f.To.IsZero() {
		args = append(args, f.To)
		clauses = append(clauses, "ts <= "+placeholder(len(args)))
	}
	if f.AgentID != "" {
		args = append(args, f.AgentID)
		clauses = append(clauses, "agent_id = "+placeholder(len(args)))
	}
	if f.Tool != "" {
		args = append(args, f.Tool)
		clauses = append(clauses, "tool = "+placeholder(len(args)))
	}
	if f.Decision != "" {
		args = append(args, f.Decision)
		clauses = append(clauses, "decision = "+placeholder(len(args)))
	}
	if f.Check != "" {
		args = append(args, f.Check)
		clauses = append(clauses, "check_stage = "+placeholder(len(args)))
	}
	if f.CapabilityTokenID != "" {
		args = append(args, f.CapabilityTokenID)
		clauses = append(clauses, "capability_token_id = "+placeholder(len(args)))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// placeholder produces a positional argument marker like "$3".
func placeholder(n int) string {
	return fmt.Sprintf("$%d", n)
}

// parseEventTime tolerates the few formats time.Time → JSON might
// produce. RFC3339Nano is the format NewEvent uses; the others are
// belt-and-braces for events emitted by older builds or replayed from
// other sources.
func parseEventTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", s)
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
