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
	"github.com/jackc/pgx/v5"
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
//
// # Chain semantics
//
// Insert advances the tamper-evident chain (Pro v2 #4, session 54):
//
//  1. BEGIN transaction.
//  2. Upsert a row in audit_chain_heads for the event's tenant and
//     SELECT FOR UPDATE its current head_hash. This serializes
//     concurrent inserts for the same tenant — two emitter workers
//     hitting Insert simultaneously will pick distinct prev_hashes
//     because Postgres releases the head lock only at COMMIT.
//  3. Compute hash = SHA-256(prev_hash || canonical_event_json).
//  4. INSERT the event row with prev_hash + hash columns populated.
//  5. UPDATE the chain head to the new hash.
//  6. COMMIT.
//
// On the very first event of a tenant, the head_hash is empty (the
// default ON CONFLICT DO NOTHING insert leaves it as ”), and the
// stored prev_hash is NULL. Subsequent rows chain off that head.
//
// The cost is one extra UPSERT + SELECT FOR UPDATE + UPDATE per
// insert (4 statements vs the prior 1). Since audit emission is
// already async behind the gateway's emitter buffer, this is hidden
// from the request hot path.
func (s *PostgresStore) Insert(ctx context.Context, e audit.Event) error {
	ts, err := parseEventTime(e.Timestamp)
	if err != nil {
		// An audit event with an unparseable timestamp shouldn't happen
		// (NewEvent always sets RFC3339Nano UTC) but if it does we use
		// "now" rather than refusing to record the event. Audit
		// emission is meant to be best-effort.
		ts = time.Now().UTC()
	}
	// Fix up the event's timestamp string to match what we'll store,
	// so the hash on the way in matches the hash any consumer would
	// recompute after loading the row back. Round-tripping RFC3339Nano
	// through time.Parse + .Format is lossless, but defensively
	// re-format here in case the source string was abbreviated.
	e.Timestamp = ts.UTC().Format(time.RFC3339Nano)

	// Canonical hash of this event, BEFORE the prev_hash is woven in
	// (that happens inside the tx with the locked head).
	canon, err := audit.CanonicalForHash(e)
	if err != nil {
		return fmt.Errorf("auditstore: canonical hash: %w", err)
	}

	var argKeysJSON []byte
	if len(e.ArgKeys) > 0 {
		argKeysJSON, err = json.Marshal(e.ArgKeys)
		if err != nil {
			return fmt.Errorf("auditstore: marshal arg_keys: %w", err)
		}
	}
	// arg_values is JSONB on the wire — pass nil when the map is
	// empty so we store SQL NULL rather than the literal "{}", which
	// the dry-run consumer reads as "redaction was disabled."
	var argValuesJSON []byte
	if len(e.ArgValues) > 0 {
		argValuesJSON, err = json.Marshal(e.ArgValues)
		if err != nil {
			return fmt.Errorf("auditstore: marshal arg_values: %w", err)
		}
	}

	// Resolve the chain-head tenant key. Old rows have NULL tenant
	// (pre-0.9); new rows always carry a non-empty tenant set by
	// gateway main.go to "default" when the operator hasn't enabled
	// multi-tenancy. We treat empty string the same as "default"
	// for the chain key to avoid accidentally creating a separate
	// chain when a misconfigured caller emits empty tenant.
	chainTenant := e.Tenant
	if chainTenant == "" {
		chainTenant = "default"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("auditstore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Ensure the head row exists for this tenant.
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_chain_heads (tenant, head_hash, head_id) VALUES ($1, '', NULL) ON CONFLICT DO NOTHING`,
		chainTenant,
	); err != nil {
		return fmt.Errorf("auditstore: ensure chain head: %w", err)
	}

	// Lock the head row to serialize chain progression for this tenant.
	var prevHash string
	if err := tx.QueryRow(ctx,
		`SELECT head_hash FROM audit_chain_heads WHERE tenant = $1 FOR UPDATE`,
		chainTenant,
	).Scan(&prevHash); err != nil {
		return fmt.Errorf("auditstore: lock chain head: %w", err)
	}

	newHash := audit.ComputeHash(prevHash, canon)
	// prev_hash is NULL only on the very first event in a tenant's
	// chain (when prevHash is "").
	var prevHashCol any = prevHash
	if prevHash == "" {
		prevHashCol = nil
	}

	const q = `
		INSERT INTO audit_events (
			ts, event_name, schema_version,
			decision, check_stage, reason,
			agent_id, session_id,
			tool, arg_keys,
			capability_token_id, intent_summary,
			latency_ms, remote_ip, upstream_status,
			root_capability_token_id, caveat_count, tenant,
			arg_values,
			prev_hash, hash,
			elevation_id
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8,
			$9, $10,
			$11, $12,
			$13, $14, $15,
			$16, $17, $18,
			$19,
			$20, $21,
			$22
		)
		RETURNING id
	`
	var insertedID int64
	if err := tx.QueryRow(ctx, q,
		ts, defaultStr(e.EventName, "intentgate.tool_call"), defaultStr(e.SchemaVersion, "1"),
		string(e.Decision), string(e.Check), e.Reason,
		e.AgentID, e.SessionID,
		e.Tool, argKeysJSON,
		e.CapabilityTokenID, e.IntentSummary,
		e.LatencyMS, e.RemoteIP, e.UpstreamStatus,
		nullableString(e.RootCapabilityTokenID), nullableInt(e.CaveatCount),
		nullableString(e.Tenant),
		argValuesJSON,
		prevHashCol, newHash,
		nullableString(e.ElevationID),
	).Scan(&insertedID); err != nil {
		return fmt.Errorf("auditstore: insert: %w", err)
	}

	// Advance the chain head. UPDATE inside the same tx as the
	// INSERT, so a crash between them rolls both back together.
	if _, err := tx.Exec(ctx,
		`UPDATE audit_chain_heads SET head_hash = $1, head_id = $2, updated_at = NOW() WHERE tenant = $3`,
		newHash, insertedID, chainTenant,
	); err != nil {
		return fmt.Errorf("auditstore: update chain head: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("auditstore: commit: %w", err)
	}
	return nil
}

// nullableString turns "" into nil so the database stores NULL rather
// than an empty string (cleaner queries, matches the audit-event
// omitempty convention).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableInt turns 0 into nil for the same reason.
func nullableInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
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
			latency_ms, remote_ip, upstream_status,
			root_capability_token_id, caveat_count, tenant,
			arg_values, elevation_id
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
			ts            time.Time
			argKeysJSON   []byte
			argValuesJSON []byte
			ev            audit.Event
			decision      string
			check         string
			rootJTI       *string
			caveatCount   *int
			tenant        *string
			elevationID   *string
		)
		if err := rows.Scan(
			&ts, &ev.EventName, &ev.SchemaVersion,
			&decision, &check, &ev.Reason,
			&ev.AgentID, &ev.SessionID,
			&ev.Tool, &argKeysJSON,
			&ev.CapabilityTokenID, &ev.IntentSummary,
			&ev.LatencyMS, &ev.RemoteIP, &ev.UpstreamStatus,
			&rootJTI, &caveatCount, &tenant,
			&argValuesJSON, &elevationID,
		); err != nil {
			return nil, fmt.Errorf("auditstore: scan: %w", err)
		}
		if rootJTI != nil {
			ev.RootCapabilityTokenID = *rootJTI
		}
		if caveatCount != nil {
			ev.CaveatCount = *caveatCount
		}
		if tenant != nil {
			ev.Tenant = *tenant
		}
		if elevationID != nil {
			ev.ElevationID = *elevationID
		}
		ev.Timestamp = ts.UTC().Format(time.RFC3339Nano)
		ev.Decision = audit.Decision(decision)
		ev.Check = audit.Check(check)
		if len(argKeysJSON) > 0 {
			_ = json.Unmarshal(argKeysJSON, &ev.ArgKeys)
		}
		if len(argValuesJSON) > 0 {
			_ = json.Unmarshal(argValuesJSON, &ev.ArgValues)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auditstore: rows iter: %w", err)
	}
	return out, nil
}

// VerifyChain walks the per-tenant chain over [from, to] in insertion
// order, recomputing each row's hash and comparing to the stored
// value. Returns the first divergence or an OK result.
//
// We scan rows ordered by id (the BIGSERIAL is monotonic per insert
// transaction commit order) rather than by ts, because two events
// with the same ts could legitimately be inserted in either id order
// inside one tx burst — id is the canonical chain order.
//
// Rows with hash = ” are pre-feature rows (gateway < 1.7); they're
// surfaced as Skipped count and don't fail verification.
func (s *PostgresStore) VerifyChain(ctx context.Context, f VerifyFilter) (VerifyResult, error) {
	tenant := f.Tenant
	if tenant == "" {
		tenant = "default"
	}

	// Build a per-verify WHERE with id ASC ordering.
	q := `
		SELECT id, ts, event_name, schema_version,
			decision, check_stage, reason,
			agent_id, session_id,
			tool, arg_keys,
			capability_token_id, intent_summary,
			latency_ms, remote_ip, upstream_status,
			root_capability_token_id, caveat_count, tenant,
			prev_hash, hash
		FROM audit_events
		WHERE COALESCE(tenant, 'default') = $1
	`
	args := []any{tenant}
	if !f.From.IsZero() {
		args = append(args, f.From)
		q += " AND ts >= $" + fmt.Sprintf("%d", len(args))
	}
	if !f.To.IsZero() {
		args = append(args, f.To)
		q += " AND ts <= $" + fmt.Sprintf("%d", len(args))
	}
	q += " ORDER BY id ASC"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("auditstore: verify query: %w", err)
	}
	defer rows.Close()

	var prevHashLink string
	out := VerifyResult{OK: true}

	for rows.Next() {
		var (
			id          int64
			ts          time.Time
			argKeysJSON []byte
			ev          audit.Event
			decision    string
			check       string
			rootJTI     *string
			caveatCount *int
			tenantCol   *string
			prevHashCol *string
			hashStored  string
		)
		if err := rows.Scan(
			&id, &ts, &ev.EventName, &ev.SchemaVersion,
			&decision, &check, &ev.Reason,
			&ev.AgentID, &ev.SessionID,
			&ev.Tool, &argKeysJSON,
			&ev.CapabilityTokenID, &ev.IntentSummary,
			&ev.LatencyMS, &ev.RemoteIP, &ev.UpstreamStatus,
			&rootJTI, &caveatCount, &tenantCol,
			&prevHashCol, &hashStored,
		); err != nil {
			return VerifyResult{}, fmt.Errorf("auditstore: verify scan: %w", err)
		}
		if rootJTI != nil {
			ev.RootCapabilityTokenID = *rootJTI
		}
		if caveatCount != nil {
			ev.CaveatCount = *caveatCount
		}
		if tenantCol != nil {
			ev.Tenant = *tenantCol
		}
		ev.Timestamp = ts.UTC().Format(time.RFC3339Nano)
		ev.Decision = audit.Decision(decision)
		ev.Check = audit.Check(check)
		if len(argKeysJSON) > 0 {
			_ = json.Unmarshal(argKeysJSON, &ev.ArgKeys)
		}

		// Pre-feature rows: hash empty + prev_hash NULL. Skip but count.
		if hashStored == "" {
			out.Skipped++
			continue
		}

		// Walk the link: each row's prev_hash must equal the previous
		// verified row's stored hash (or be NULL only on the first
		// verified row of the chain).
		var prevFromRow string
		if prevHashCol != nil {
			prevFromRow = *prevHashCol
		}
		// If this is the first verified row in the window, we don't
		// have a prevHashLink to compare against (the previous row may
		// be outside the window). Trust the stored prev_hash for the
		// recompute; the chain integrity from "true beginning" can be
		// verified by widening the window to the start of time.
		if out.Verified > 0 {
			if prevFromRow != prevHashLink {
				out.OK = false
				out.BrokenAt = &VerifyBreak{
					ID:           id,
					Timestamp:    ts,
					StoredHash:   hashStored,
					ExpectedHash: prevHashLink,
					Reason:       "prev_hash mismatch (chain link broken — row inserted/deleted)",
				}
				return out, nil
			}
		}

		canon, err := audit.CanonicalForHash(ev)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("auditstore: canonical hash: %w", err)
		}
		recomputed := audit.ComputeHash(prevFromRow, canon)
		if recomputed != hashStored {
			out.OK = false
			out.BrokenAt = &VerifyBreak{
				ID:           id,
				Timestamp:    ts,
				StoredHash:   hashStored,
				ExpectedHash: recomputed,
				Reason:       "hash mismatch (row body tampered)",
			}
			return out, nil
		}

		out.Verified++
		prevHashLink = hashStored
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("auditstore: verify iter: %w", err)
	}

	// Stamp the per-tenant chain-head telemetry onto the result so
	// console-pro can render "chain last advanced N seconds ago" on
	// /audit/verify. Best effort: a tenant with no events has no row
	// in audit_chain_heads, which the scan surfaces as ErrNoRows; we
	// leave HeadID + HeadAt zero in that case. A genuine query error
	// is logged via the returned error so the caller can degrade
	// gracefully — verify already succeeded, we shouldn't fail the
	// whole call over a freshness indicator.
	var (
		headID *int64
		headAt time.Time
	)
	herr := s.pool.QueryRow(ctx,
		`SELECT head_id, updated_at FROM audit_chain_heads WHERE tenant = $1`,
		tenant,
	).Scan(&headID, &headAt)
	if herr == nil {
		if headID != nil {
			out.HeadID = *headID
		}
		out.HeadAt = headAt.UTC()
	} else if !errors.Is(herr, pgx.ErrNoRows) {
		// Don't fail the whole verify on a head-telemetry lookup error
		// — the verify result is the operator's primary signal. Just
		// leave the fields zero; console-pro hides the indicator when
		// HeadAt is zero.
		return out, nil
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
	if f.Tenant != "" {
		args = append(args, f.Tenant)
		clauses = append(clauses, "tenant = "+placeholder(len(args)))
	}
	if f.ElevationID != "" {
		args = append(args, f.ElevationID)
		clauses = append(clauses, "elevation_id = "+placeholder(len(args)))
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
