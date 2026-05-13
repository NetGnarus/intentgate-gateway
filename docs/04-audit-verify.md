# Querying audit and verifying the chain

This guide covers querying IntentGate's audit log to investigate what an agent did, and running the chain-verify endpoint to prove the log hasn't been tampered with. Roughly 10 minutes to read; longer if you wire the verify endpoint into your SOC's regular evidence cadence.

Prerequisite: a gateway with audit persistence enabled. That means `INTENTGATE_POSTGRES_URL` and `INTENTGATE_AUDIT_PERSIST=true` — the in-memory quickstart from Guide 01 doesn't satisfy this. Add Postgres before continuing.

## What gets recorded

Every authorization decision the gateway makes emits one row into `audit_events` in Postgres. That includes:

- **Allow events** — `tools/call` that passed all four checks. The reason field carries the policy rule that fired ("read-only tool" or "routine write tool" by default).
- **Block events** — anything denied at any stage. The `check` field tells you which stage (`capability`, `intent`, `policy`, or `budget`) and the `reason` field explains why.
- **Escalate events** — calls that policy returned `{escalate: true}` for. These pause for human approval; a follow-up audit event records the eventual approve/reject/timeout outcome.
- **Admin events** — `mint`, `revoke`, `promote_policy`, and other operator actions. Useful for "who changed the policy at 3am" investigations.

Each row carries a cryptographic hash linking it to the previous row in the same tenant's chain. Tampering with any historical row breaks every row that comes after it — which is exactly what `/v1/admin/audit/verify` exists to detect.

## Querying recent activity

The `GET /v1/admin/audit` endpoint returns paginated events with filters for everything you'd want to filter on:

```sh
# Last 20 events, any decision, any agent
curl -sS \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit?limit=20" | jq
```

The response shape:

```json
{
  "events": [
    {
      "ts":             "2026-05-13T08:42:01.157892Z",
      "event":          "intentgate.tool_call",
      "schema_version": "1",
      "decision":       "block",
      "check":          "policy",
      "reason":         "transfer at or above 5000 EUR threshold — admin approval required",
      "tenant":         "default",
      "agent_id":       "agent-finance",
      "tool":           "transfer_funds",
      "arg_keys":       ["from_account", "to_account", "amount_eur"],
      "capability_token_id":      "agQg6WvM9es6F9R1qsO2iQ",
      "root_capability_token_id": "agQg6WvM9es6F9R1qsO2iQ",
      "caveat_count":   2,
      "pending_id":     "8a3f9c1b...",
      "intent_summary": "Pay invoice INV-1002 to vendor G42",
      "latency_ms":     42,
      "remote_ip":      "10.0.0.42",
      "upstream_status": 0
    },
    ...
  ],
  "limit":  20,
  "offset": 0
}
```

### Useful filter combinations

**All blocks in the last hour** — the SOC "what's been rejected?" query:

```sh
FROM=$(date -u -v-1H +%FT%TZ)   # macOS
# FROM=$(date -u -d '1 hour ago' +%FT%TZ)   # Linux

curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit?decision=block&from=$FROM&limit=200" \
  | jq '.events[] | {ts, agent_id, tool, check, reason}'
```

**Everything one specific agent did** — incident response after a credential leak suspicion:

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit?agent_id=agent-finance&limit=500" | jq
```

**Every call to a specific tool** — "did anyone successfully call `transfer_funds` last week?":

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit?tool=transfer_funds&decision=allow&from=2026-05-06T00:00:00Z&limit=1000" \
  | jq '.events[] | {ts, agent_id, arg_keys, reason}'
```

**Decisions made under a JIT elevation** — "show me every privileged operation an operator performed during a break-glass session":

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit?elevation_id=$ELEVATION_ID&limit=200" | jq
```

### Filter parameters reference

| Parameter | Type | Meaning |
|---|---|---|
| `from` | RFC3339 | Inclusive lower bound on `ts` |
| `to` | RFC3339 | Inclusive upper bound on `ts` |
| `agent_id` | string | Exact-match filter on `agent_id` |
| `tool` | string | Exact-match filter on `tool` |
| `decision` | `allow` / `block` / `escalate` | Filter by outcome |
| `check` | `capability` / `intent` / `policy` / `budget` / `upstream` | Which stage fired |
| `jti` | string | Capability token ID (the `jti` claim) |
| `elevation_id` | string | JIT-elevation correlation ID |
| `tenant` | string | Multi-tenant scope (superadmin only) |
| `limit` | int | Page size, default 100, max 1000 |
| `offset` | int | Pagination offset |
| `count` | `true` | Additionally return total row count (potentially expensive) |

The console-pro `/audit` page wraps all of this with a UI for filter chips, free-text search, and CSV / NDJSON download. If you're building automation against the API directly, the `/v1/admin/audit/export` endpoint streams the same filtered set in CSV (default, spreadsheet-friendly) or NDJSON (`format=json`, lossless including nested arg_values) with the same query parameters.

## Verifying the chain

The audit chain proves that audit events haven't been retroactively edited. Each row's hash is `SHA-256(prev_row_hash || canonical_event_json)`; mutate any historical row's content and every row downstream from it produces a different hash than what's stored.

The `GET /v1/admin/audit/verify` endpoint walks the entire per-tenant chain in `id` order, recomputes each hash, and reports either OK or the first divergence:

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit/verify" | jq
```

Output on a healthy chain:

```json
{
  "ok":       true,
  "tenant":   "default",
  "verified": 12345,
  "skipped":  0,
  "head_at":  "2026-05-13T08:42:01.157892Z",
  "head_id":  12345
}
```

- `verified` — count of events whose hash matched.
- `skipped` — count of pre-feature rows (gateway < 1.7) that don't have a hash. These don't fail verification; they just predate the chain.
- `head_at` — when the chain last advanced. If this is far in the past, your gateway has stopped writing audit events, which is itself a problem worth investigating.
- `head_id` — the most recent event's id. Useful for "show me the latest event": `GET /v1/admin/audit?limit=1`.

Output on a tampered chain:

```json
{
  "ok":       false,
  "tenant":   "default",
  "verified": 7421,
  "broken_at": {
    "id":            7422,
    "ts":            "2026-04-02T11:33:08.444Z",
    "stored_hash":   "3d498a2d4401d2e969f65fd178ad27a21830fc0036e76b336e7a2edceec3942e",
    "expected_hash": "3e97a0044aac50713d4bb2a464b0206496f0afe74fbfc1ab5d6c6f083df20ee2",
    "reason":        "hash mismatch (row body tampered)"
  }
}
```

The `broken_at` block tells you exactly which row diverged. There are two reasons a chain breaks in practice:

- **`hash mismatch (row body tampered)`** — the row content was edited after insert. The stored hash was computed over the original bytes; the recompute uses the current bytes; they don't match.
- **`prev_hash mismatch (chain link broken — row inserted/deleted)`** — a row was inserted or deleted, so the link from row N to row N+1 broke even though both rows are individually consistent.

When verify fails, query the offending row directly to see what's in it:

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/v1/admin/audit?limit=1&offset=$((7422 - 1))" | jq
```

## Using verify as compliance evidence

The chain verify endpoint is the load-bearing artifact for two specific compliance asks:

**SOC 2 CC7.2 (system monitoring)** — auditors want to see that authorization decisions are logged, that the log isn't editable, and that you regularly check it. The pattern most customers settle on:

1. Run `GET /v1/admin/audit/verify` daily via cron, log the output to a separate evidence bucket (S3 / Azure Blob with object lock).
2. Pair each verify result with a `GET /v1/admin/audit/export?format=json&from=<24h ago>` so you have both the events and the proof they weren't edited.
3. The daily evidence pack ships the JSON verify result + the NDJSON event export + a manifest. Auditors get one folder per audit period.

The IntentGate Pro console (the `/audit/verify` page) automates this — it runs verify on a schedule, surfaces a "last advanced N ago" indicator on the dashboard, and offers a one-click "compliance pack" download that bundles verify + export + manifest.

**EU AI Act Article 12 (logging obligations for high-risk AI systems)** — the regulation requires logging of system operations with traceability of which AI system handled which decision. The audit event's `agent_id` + `capability_token_id` + `intent_summary` + `policy_rule` chain answers the regulator's "which model decided this, on whose behalf, with what stated purpose" question in one query.

For the full evidence pack workflow (including the manifest format auditors actually want), the deployment runbook section 8 has the operational details. Request via [/contact](https://intentgate.app/contact).

## What's next

- **The console-pro audit UI** at `/audit` — same data as the API, with filter chips and CSV download. If you're investigating an incident, that's the friendlier surface.
- **The console-pro audit-verify UI** at `/audit/verify` — runs the verify endpoint, surfaces chain-head freshness, and exposes the compliance pack download.
- **SIEM forwarding** — for shops with existing Splunk / Datadog / Sentinel investments, the gateway can fan audit events out to those backends in addition to Postgres. See the SIEM section of the gateway [README](../README.md).
- **Webhook emission** — high-signal events (denies, escalates, step-up required) can be POSTed to a chat-ops or paging webhook with HMAC signatures. Configured via `INTENTGATE_WEBHOOK_URL`.

This is the last of the four MVP guides. Once you've got a gateway running with a custom policy, an agent calling tools through it, and verified audit telling you what happened, you've covered the customer journey from quickstart to production-ready operations. The deployment runbook is the next step up for production patterns; the gateway README and individual repo READMEs cover everything else.
