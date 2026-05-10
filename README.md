# IntentGate Gateway

[![CI](https://github.com/NetGnarus/intentgate-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/NetGnarus/intentgate-gateway/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/NetGnarus/intentgate-gateway.svg)](https://pkg.go.dev/github.com/NetGnarus/intentgate-gateway)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)
[![Container](https://img.shields.io/badge/ghcr.io-intentgate--gateway-2188ff.svg)](https://github.com/NetGnarus/intentgate-gateway/pkgs/container/intentgate-gateway)

A self-hosted authorization gateway for AI agents.

> **Performance** (single-replica, in-memory dev install): **2,000 RPS at p50 = 0.77 ms, p99 = 1.50 ms, 100% success**. Full numbers and reproducer in [`BENCHMARKS.md`](BENCHMARKS.md); rerun with `./scripts/bench.sh` against any IntentGate gateway you can reach.

The gateway sits between an AI agent and the tool servers it wants to call.
It intercepts every tool call, evaluates it through a four-check pipeline
(**capability, intent, policy, budget**), and either forwards the call
upstream or blocks it. Every decision emits a structured audit event.

It is **self-hosted**: you run it inside your perimeter, on your
Kubernetes cluster, on your VM, or in your laptop. No IntentGate-hosted
services are involved. Agent prompts, tool arguments, and audit events
never leave your network.

This repository is the open-source core (Apache 2.0). The advanced admin
console, multi-tenant control plane, advanced audit service, and
fine-tuned intent extractor are commercial products in separate, private
repositories.

## Companion repositories

| Repo | Purpose |
| ---- | ------- |
| [intentgate-gateway](https://github.com/NetGnarus/intentgate-gateway) | Go gateway with the four-check pipeline (this repo). |
| [intentgate-extractor](https://github.com/NetGnarus/intentgate-extractor) | Python FastAPI service that turns a free-form prompt into a structured intent (`allowed_tools`, `forbidden_tools`, `summary`). Used by the gateway's intent check. |
| [intentgate-sdk-python](https://github.com/NetGnarus/intentgate-sdk-python) | Python SDK for agents — three lines to call the gateway with typed exceptions per check. |
| [intentgate-helm](https://github.com/NetGnarus/intentgate-helm) | Helm chart that deploys the gateway, extractor, and Redis to a Kubernetes cluster. |

## Status

`v0.1.0` — **HTTP + MCP framing + full four-check pipeline + audit emission.**

The server boots and accepts requests on three endpoints:

- `GET  /healthz` — liveness probe.
- `POST /v1/tool-call` — simple flat JSON shape, kept for ad-hoc curl testing.
- `POST /v1/mcp` — JSON-RPC 2.0 / Model Context Protocol. Runs the full four-check pipeline:
  - **Capability** (Bearer token, Macaroon-style HMAC chain). Caveats are evaluated against the requested tool.
  - **Intent.** When `X-Intent-Prompt` is supplied and an extractor is configured, the gateway calls the [extractor service](https://github.com/NetGnarus/intentgate-extractor), gets a structured intent (`allowed_tools` / `forbidden_tools`), and verifies the requested tool is permitted.
  - **Policy.** OPA-backed Rego engine (embedded). Customer policies can express thresholds, time-of-day rules, agent-specific overrides, and arbitrary business logic. A starter policy is shipped; override via `INTENTGATE_POLICY_FILE`.
  - **Budget.** Per-token call counters via a `max_calls` caveat. Backed by Redis in production (multi-replica safe) or an in-memory store in dev.

All four data-plane checks are live. Calls that pass every stage are
either **forwarded to the configured upstream MCP tool server** (when
`INTENTGATE_UPSTREAM_URL` is set) or returned with a stub allow (when
the gateway is run standalone for SDK tests / smoke targets). See the
"Upstream forwarding" section below.

## Quick start

Requires **Go 1.25+**.

```sh
make build
./bin/gateway
```

Or in one step:

```sh
make run
```

The server listens on `:8080` by default. Override with the
`INTENTGATE_ADDR` environment variable.

In another shell, smoke-test all three endpoints at once:

```sh
make smoke
```

That hits `/healthz`, `/v1/tool-call`, and `/v1/mcp` and prints each
response. Equivalent curl invocations by hand:

```sh
# liveness
curl -s http://localhost:8080/healthz

# REST shape (legacy / dev convenience)
curl -sX POST http://localhost:8080/v1/tool-call \
  -H 'Content-Type: application/json' \
  -d '{"tool":"read_invoice","args":{"id":"123"},"agent_id":"finance-copilot-v3"}'

# MCP / JSON-RPC 2.0 shape (canonical)
curl -sX POST http://localhost:8080/v1/mcp \
  -H 'Content-Type: application/json' \
  -d '{
        "jsonrpc":"2.0",
        "id":1,
        "method":"tools/call",
        "params":{
          "name":"read_invoice",
          "arguments":{"id":"123"}
        }
      }'
```

The MCP response wraps the gateway's decision in `result._intentgate`
(vendor extension; spec-compliant clients ignore it):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type":"text","text":"stub: pipeline not implemented; allow"}],
    "isError": false,
    "_intentgate": {
      "decision": "allow",
      "reason":   "stub: pipeline not implemented",
      "latency_ms": 0
    }
  }
}
```

Three additional MCP methods are accepted as **pure passthroughs**
(no four-check pipeline, no audit event):

- `initialize` — JSON-RPC handshake. Forwarded to the upstream when
  `INTENTGATE_UPSTREAM_URL` is set; falls back to a minimal local
  response (advertising `serverInfo.name = "intentgate"`) so a
  standalone gateway still completes a clean MCP handshake.
- `tools/list` — tool discovery. Forwarded to the upstream when set;
  returns `{"tools": []}` otherwise.
- `ping` — keepalive. Forwarded to the upstream when set; returns
  `{}` otherwise.

These don't carry tool names so the four checks (capability, intent,
policy, budget) don't apply. Audit events are reserved for `tools/call`
authorization decisions; flooding the audit channel with handshake
noise would dilute SOC signal.

Other methods return JSON-RPC `MethodNotFound` (-32601).

## Use it from an agent

The [Python SDK](https://github.com/NetGnarus/intentgate-sdk-python)
hides the HTTP plumbing and turns each check failure into a typed
exception:

```python
from intentgate import Gateway, CapabilityError, IntentError, PolicyError, BudgetError

gw = Gateway("http://localhost:8080", token=TOKEN)

try:
    result = gw.call(
        tool="read_invoice",
        arguments={"id": "123"},
        intent_prompt="Process today's AP invoices",
    )
except CapabilityError as e:
    ...   # token is missing, expired, tampered, or doesn't permit this tool
except IntentError as e:
    ...   # the requested tool doesn't fit the declared intent
except PolicyError as e:
    ...   # the OPA policy denied the call
except BudgetError as e:
    ...   # the token's max_calls budget is exhausted
```

A TypeScript SDK is on the v1.0 roadmap.

## Project layout

```
cmd/gateway/          # gateway binary entrypoint, graceful shutdown
cmd/igctl/            # developer CLI: gen-key / mint / decode
internal/server/      # HTTP server, middleware (request logger, panic recovery)
internal/handlers/    # /healthz, /v1/tool-call, /v1/mcp handlers
internal/mcp/         # JSON-RPC 2.0 envelope, MCP method types, error codes
internal/capability/  # Macaroon-style HMAC capability tokens, caveats, codec
internal/extractor/   # HTTP client for the intent extractor + LRU cache
internal/policy/      # OPA Rego engine + embedded default_policy.rego
internal/budget/      # Per-token call counters: MemoryStore + RedisStore
internal/audit/       # OCSF-lite Event + Emitter (stdout / none)
pkg/                  # reserved for public packages (future SDK integration types)
Dockerfile            # multi-stage: build in golang:1.25-alpine, run in distroless
Makefile              # build / run / test / docker / smoke / mint / gen-key
.github/workflows/    # CI (test + build on PRs) and release (publish image to GHCR)
```

The repository follows the standard Go layout: `cmd/` holds main packages,
`internal/` holds packages the wider Go ecosystem cannot import, `pkg/`
holds packages we expose for external use.

## Docker

Build locally:

```sh
make docker
make docker-run
```

The runtime image is `gcr.io/distroless/static:nonroot`, ~2 MB, no shell,
runs as a non-root user.

Pull the official multi-arch image (linux/amd64, linux/arm64) from GHCR:

```sh
docker pull ghcr.io/netgnarus/intentgate-gateway:latest
docker run --rm -p 8080:8080 ghcr.io/netgnarus/intentgate-gateway:latest
```

Tagged images (`:v0.1.0`, `:v0.1`, `:0.1.0`) are published automatically
when a `vX.Y.Z` git tag is pushed — see `.github/workflows/release.yml`.

## Configuration

| Env var                         | Default | Description                                                                                              |
| ------------------------------- | ------- | -------------------------------------------------------------------------------------------------------- |
| `INTENTGATE_ADDR`               | `:8080` | HTTP listen address.                                                                                     |
| `INTENTGATE_MASTER_KEY`         | _unset_ | base64url-encoded HMAC key for capability tokens. If unset, an ephemeral key is generated and logged.    |
| `INTENTGATE_REQUIRE_CAPABILITY` | `false` | When `true`, `/v1/mcp` rejects calls without a valid Bearer capability token (instead of allowing them). |
| `INTENTGATE_EXTRACTOR_URL`      | _unset_ | Base URL of the [intent extractor service](../extractor/). When unset, the intent check is disabled.     |
| `INTENTGATE_REQUIRE_INTENT`     | `false` | When `true`, `/v1/mcp` rejects calls without an `X-Intent-Prompt` header.                                |
| `INTENTGATE_POLICY_FILE`        | _unset_ | Path to a customer Rego policy file. When unset, the embedded `default_policy.rego` is used.             |
| `INTENTGATE_REDIS_URL`          | _unset_ | Redis URL for the budget counter store, e.g. `redis://localhost:6379/0`. When unset, an in-memory store is used (single-replica only). |
| `INTENTGATE_REQUIRE_BUDGET`     | `false` | When `true`, `/v1/mcp tools/call` requires a verified capability token before the budget stage runs.     |
| `INTENTGATE_AUDIT_TARGET`       | `stdout`| Where audit events go. `stdout` (default) emits one JSON event per line; `none` disables emission.       |
| `INTENTGATE_UPSTREAM_URL`       | _unset_ | URL of the downstream MCP tool server. When unset, the gateway returns a stub allow for any authorized call (useful for SDK tests / smokes). |
| `INTENTGATE_UPSTREAM_TIMEOUT_MS`| `30000` | Per-call upstream timeout in milliseconds.                                                               |
| `INTENTGATE_POSTGRES_URL`       | _unset_ | libpq DSN for a durable revocation store. Empty falls back to in-memory (single-replica only).           |
| `INTENTGATE_ADMIN_TOKEN`        | _unset_ | Shared secret guarding `/v1/admin/*` endpoints (mint, revoke, list-revocations). Empty disables admin API. |
| `INTENTGATE_METRICS_ENABLED`    | _unset_ | `true` to register `GET /metrics` on the public port. Off by default — exposing metrics on the public port is an info-disclosure risk for naive deploys. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`   | _unset_ | Standard OTel env var. When set, the gateway emits one span per HTTP request via OTLP gRPC.              |

More configuration arrives with the intent extractor client, policy
engine, and storage layers.

## Capability tokens (the first of four checks)

`/v1/mcp` verifies Macaroon-style HMAC-SHA256 capability tokens passed
in the `Authorization: Bearer <token>` header. Tokens carry caveats
(agent_lock, expiry, tool whitelist, tool blacklist) signed in a chain
under the gateway's master key. Holders can attenuate a token (append
caveats to make it more restrictive) without the master key — that's
the property that makes safe parent → sub-agent delegation possible.

Spin it up end-to-end:

```sh
# 1. Generate a master key and export it
export INTENTGATE_MASTER_KEY=$(make gen-key)

# 2. Run the gateway in strict mode (rejects calls without tokens)
INTENTGATE_REQUIRE_CAPABILITY=true ./bin/gateway

# 3. In another shell, mint a token allowing only read_invoice
TOKEN=$(./bin/igctl mint --subject finance-copilot-v3 --tools "read_invoice" --ttl 1h)

# 4. Smoke test: read_invoice allowed, send_email blocked
make smoke-cap TOKEN=$TOKEN

# 5. Tampered tokens are rejected
make smoke-cap-bad TOKEN=$TOKEN

# 6. Strict mode rejects unauthenticated calls
make smoke-cap-strict
```

`igctl decode <token>` pretty-prints a token's contents (without
verifying the signature) for debugging.

## Token revocation

Capability tokens are stateless: once minted they remain valid until
their expiry caveat fires. **Revocation** is the operator's emergency
stop — invalidate a token before its natural expiry without rotating
the master key (which would invalidate every other outstanding token).

Configure a revocation store via `INTENTGATE_POSTGRES_URL`:

```sh
export INTENTGATE_POSTGRES_URL="postgres://intentgate:secret@db:5432/intentgate"
export INTENTGATE_ADMIN_TOKEN="$(openssl rand -hex 32)"
./bin/gateway
```

The gateway runs an embedded migration at startup creating a single
`revoked_tokens` table. When unset, an in-memory store is used (fine
for dev; lost on restart, single-replica only).

The capability check consults the store on every request after the
HMAC chain verifies. A revoked token is rejected with the same
`-32010 capability_failed` JSON-RPC code as any other failed token,
with reason `token revoked`. A revocation-store outage **fails closed**
(treats every token as revoked); a partial outage of revocation must
not become a quiet authorization bypass.

To revoke a token, find its JTI and call the admin API:

```sh
# Find the JTI of a token you've issued
./bin/igctl decode "$TOKEN" | jq .jti
# "01HXY..."

# Revoke it
./bin/igctl revoke \
  --gateway http://localhost:8080 \
  --admin-token "$INTENTGATE_ADMIN_TOKEN" \
  --jti 01HXY... \
  --reason "leaked in PR comment"
```

Or list current revocations:

```sh
curl -sH "Authorization: Bearer $INTENTGATE_ADMIN_TOKEN" \
  http://localhost:8080/v1/admin/revocations | jq .
```

### Minting tokens via the admin API

`POST /v1/admin/mint` issues a fresh capability token signed under the
gateway's master key. It is the operator-facing path for handing a
brand-new agent its first credential — equivalent to `igctl mint`, but
exposed over HTTP so the admin UI can drive it.

```sh
curl -sH "Authorization: Bearer $INTENTGATE_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
           "subject":     "finance-copilot-v3",
           "ttl_seconds": 3600,
           "tools":       ["read_invoice", "list_invoices"],
           "max_calls":   100
         }' \
     http://localhost:8080/v1/admin/mint | jq .
```

Response:

```json
{
  "token":      "eyJ2IjoxLCJqdGkiOiI...",
  "jti":        "AbC1234...",
  "subject":    "finance-copilot-v3",
  "expires_at": "2026-05-09T16:00:00Z"
}
```

The endpoint is unavailable when `INTENTGATE_MASTER_KEY` is unset
(returns `503`); without a key the gateway can't sign anything. Every
mint emits an audit event (`tool: "admin/mint"`, decision `allow`,
including the JTI and subject) so SOC has a record of who issued what.

## Observability

The gateway exposes Prometheus metrics on `GET /metrics` (when
`INTENTGATE_METRICS_ENABLED=true`) and emits OpenTelemetry spans (when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set).

**Metrics published** (all under the `intentgate_gateway_` namespace):

| Metric | Type | Labels | Purpose |
| ------ | ---- | ------ | ------- |
| `http_requests_total` | counter | `method`, `route`, `status` (class) | Request rate, error rate. |
| `http_request_duration_seconds` | histogram | `method`, `route` | End-to-end gateway latency. |
| `check_decisions_total` | counter | `check`, `decision` | How often each of the four checks (plus `upstream`) allows / blocks / skips. |
| `check_duration_seconds` | histogram | `check` | Per-check evaluation cost. |
| `upstream_forward_total` | counter | `outcome` | Successful forwards vs the four failure modes. |
| `upstream_forward_duration_seconds` | histogram | `outcome` | Upstream call latency by outcome. |
| `revocation_lookups_total` | counter | `result` | Hot-path revocation store activity. |
| `revocation_lookup_duration_seconds` | histogram | _(none)_ | Revocation store latency. |

Cardinality is bounded by design: no labels by tool name, agent ID, or
JTI. Operators who want per-tool slices should enrich at the audit
layer (which has no cardinality constraints) and aggregate downstream.

**Tracing.** Setting `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g.
`otel-collector.observability:4317`) makes the gateway emit one span
per HTTP request. The full set of OpenTelemetry SDK env vars is
honored (samplers, resource attributes, etc.) — see the OTel docs.
A request span shows the four checks plus the upstream forward as
nested attributes.

## Audit events

Every authorization decision (allow or block at any of the four
stages) emits one structured JSON event on stdout. The shape is
OCSF-lite: easy to ingest into Splunk, Datadog, Sentinel, or any
stack that consumes line-delimited JSON.

Sample event for a blocked policy decision:

```json
{
  "ts":                   "2026-05-08T22:30:11.452Z",
  "event":                "intentgate.tool_call",
  "schema_version":       "1",
  "decision":             "block",
  "check":                "policy",
  "reason":               "transfer above 10000 EUR threshold",
  "agent_id":             "finance-copilot-v3",
  "session_id":           "sess_abc",
  "tool":                 "transfer_funds",
  "arg_keys":             ["amount_eur"],
  "capability_token_id":  "Z1ssWBrtbGjV...",
  "intent_summary":       "Pay vendor invoice from Globex",
  "latency_ms":           4,
  "remote_ip":            "127.0.0.1:53104"
}
```

`arg_keys` carries field names but never values — argument values may
contain sensitive data (PII, financial details, credentials) and are
deliberately omitted from the audit log.

Events appear interleaved with normal request logs on stdout. To
isolate audit lines:

```sh
./bin/gateway 2>&1 | grep '"event":"intentgate.tool_call"'
```

In production, pipe stdout through a log shipper (vector, fluent-bit,
promtail) into your SIEM.

## Upstream forwarding

When `INTENTGATE_UPSTREAM_URL` points at a downstream MCP tool server,
the gateway forwards every authorized `tools/call` to that server,
preserving the JSON-RPC `id` and `params`. The upstream's response is
returned to the agent unchanged, with the gateway's per-call decision
metadata merged into `result._intentgate` so callers can see the
gateway's verdict alongside the tool's output:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "invoice 123 has 2 line items"}],
    "isError": false,
    "_intentgate": {
      "decision":   "allow",
      "reason":     "forwarded",
      "latency_ms": 8
    }
  }
}
```

Operational failure modes (timeout, transport error, upstream non-2xx)
return JSON-RPC `CodeInternalError` to the agent **and** emit an audit
event with `check: "upstream"` and `decision: "block"`, distinguishing
"gateway authorized but couldn't deliver" from "gateway blocked at one
of the four checks". JSON-RPC errors returned by the upstream itself
(a 200 OK carrying an error object — for example, "tool says no") are
NOT considered failures: the gateway successfully delivered the call,
so the audit event records `decision: "allow"` with the upstream's
HTTP status and the upstream's body is passed through unchanged.

When `INTENTGATE_UPSTREAM_URL` is unset, the gateway returns its own
stub allow for any authorized call:

```json
{
  "result": {
    "content": [{"type": "text", "text": "stub: no upstream configured; gateway authorized this call"}],
    "isError": false,
    "_intentgate": {"decision": "allow", "reason": "stub: no upstream configured", "latency_ms": 0}
  }
}
```

This is useful for the SDK's test suite, the gateway's smoke targets,
and any deployment validating the auth pipeline before wiring a real
upstream.

## Policy authoring

The default policy lives at `internal/policy/default_policy.rego` and
demonstrates a realistic mix: read-only tools allowed, routine writes
allowed, `transfer_funds` split on a 10,000 EUR threshold,
destructive tools blocked outright.

To override, copy that file, edit, and point the gateway at it:

```sh
cp internal/policy/default_policy.rego /etc/intentgate/policy.rego
$EDITOR /etc/intentgate/policy.rego
INTENTGATE_POLICY_FILE=/etc/intentgate/policy.rego ./bin/gateway
```

The required entry point is `data.intentgate.policy.decision` returning
`{"allow": <bool>, "reason": <string>}`. The gateway treats any other
shape (or a runtime error) as fail-closed (deny). Policies see this
input shape:

```
input.tool          string
input.args          object
input.agent_id      string  (from the verified capability token)
input.intent        object  (optional; populated when intent extraction ran)
  .summary, .allowed_tools, .forbidden_tools, .confidence
input.capability    object
  .subject
```

## Roadmap

**v0.1 — done.** A friendly design partner can `helm install`, point an
agent at the gateway, and exercise the full four-check pipeline.

- [x] HTTP skeleton, `/v1/tool-call` and `/healthz`
- [x] MCP / JSON-RPC request parsing (`/v1/mcp`, `tools/call` only)
- [x] Capability tokens (HMAC-SHA256, Macaroon-style attenuation chain)
- [x] Intent extractor client + intent check
- [x] Embedded OPA policy evaluation
- [x] Budget enforcement (Redis-backed)
- [x] Audit log emission (OCSF-lite JSON to stdout)
- [x] Python SDK ([intentgate-sdk-python](https://github.com/NetGnarus/intentgate-sdk-python))
- [x] Helm chart ([intentgate-helm](https://github.com/NetGnarus/intentgate-helm))

**v0.1 → v1.0 — next.** Production hardening based on design-partner
deployments.

- [x] Upstream proxying for `tools/call` — forwards authorized calls to a configured downstream MCP server (`INTENTGATE_UPSTREAM_URL`)
- [x] Upstream proxying for `tools/list`, `initialize`, `ping` — pure passthrough; local fallbacks when no upstream so a standalone gateway still handshakes cleanly
- [x] Token revocation list — durable Postgres store + in-memory dev fallback; admin API at `/v1/admin/revoke`; `igctl revoke` CLI
- [x] Mint over admin API — `POST /v1/admin/mint` issues a fresh capability token under the gateway's master key (subject lock + optional TTL, tool whitelist, max-call cap), audit-logged like every other admin action
- [x] Prometheus `/metrics` endpoint with per-check counters and histograms (`INTENTGATE_METRICS_ENABLED=true`)
- [x] OpenTelemetry tracing via OTLP gRPC (`OTEL_EXPORTER_OTLP_ENDPOINT`)
- [ ] TypeScript SDK
- [ ] Taint propagation (data-flow side of the budget check)
- [ ] AI Act Annex IV evidence pack
- [x] Performance benchmarks — `scripts/bench.sh` sweeps request rates with vegeta, breaks latency down by check stage from `/metrics`, writes a self-contained `BENCHMARKS.md` in one command. Re-run any time the pipeline changes.

## Development

```sh
make fmt    # gofmt -s -w .
make vet    # go vet ./...
make test   # go test -race ./...
make tidy   # go mod tidy
```

CI runs `vet`, `test`, and a Docker build on every PR — see
`.github/workflows/ci.yml`.

## Contributing

The gateway is Apache 2.0 and welcomes community contributions. A formal
DCO sign-off process and `CONTRIBUTING.md` are coming with the v0.1 →
v1.0 polish pass. For now, please open an issue to discuss any
non-trivial change before sending a PR.

## Security

If you find a security vulnerability, please **do not** open a public
issue. Email security@netgnarus.com (or open a GitHub Security Advisory
on this repo) and we'll respond within two business days.
