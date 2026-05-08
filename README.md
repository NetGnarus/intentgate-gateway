# IntentGate Gateway

A self-hosted authorization gateway for AI agents.

The gateway sits between an AI agent and the tool servers it wants to call.
It intercepts every tool call, evaluates it through a four-check pipeline
(capability, intent, policy, budget), and either forwards the call upstream
or blocks it.

**License: Apache 2.0.** This repository is the open-source core of
IntentGate. The advanced admin console, multi-tenant control plane, advanced
audit service, and fine-tuned intent extractor are commercial products in
separate, private repositories — see the
[deployment architecture](../intentgate_pitch_kit_6.html) for the full picture.

## Status

`v0.1.0-dev` — **HTTP + MCP framing + full four-check pipeline.**

The server boots and accepts requests on three endpoints:

- `GET  /healthz` — liveness probe.
- `POST /v1/tool-call` — simple flat JSON shape, kept for ad-hoc curl testing.
- `POST /v1/mcp` — JSON-RPC 2.0 / Model Context Protocol. Runs the full four-check pipeline:
  - **Capability** (Bearer token, Macaroon-style HMAC chain). Caveats are evaluated against the requested tool.
  - **Intent.** When `X-Intent-Prompt` is supplied and an extractor is configured, the gateway calls the [extractor service](../extractor/), gets a structured intent (`allowed_tools` / `forbidden_tools`), and verifies the requested tool is permitted.
  - **Policy.** OPA-backed Rego engine (embedded). Customer policies can express thresholds, time-of-day rules, agent-specific overrides, and arbitrary business logic. A starter policy is shipped; override via `INTENTGATE_POLICY_FILE`.
  - **Budget.** Per-token call counters via a `max_calls` caveat. Backed by Redis in production (multi-replica safe) or an in-memory store in dev.

All four data-plane checks are now live. Calls that pass every stage
are allowed with a stub reason — the actual upstream-tool-server proxy
arrives in a later session.

## Quick start

Requires **Go 1.22+**.

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

Methods other than `tools/call` currently return a JSON-RPC
`MethodNotFound` (-32601) error.

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
Dockerfile            # multi-stage: build in golang:1.22-alpine, run in distroless
Makefile              # build / run / test / docker / smoke / mint / gen-key
```

The repository follows the standard Go layout: `cmd/` holds main packages,
`internal/` holds packages the wider Go ecosystem cannot import, `pkg/`
holds packages we expose for external use.

## Docker

```sh
make docker
make docker-run
```

The runtime image is `gcr.io/distroless/static:nonroot`, ~2 MB, no shell,
runs as a non-root user.

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

## v0.1 roadmap

- [x] HTTP skeleton, `/v1/tool-call` and `/healthz`
- [x] MCP / JSON-RPC request parsing (`/v1/mcp`, `tools/call` only)
- [x] Capability tokens (HMAC-SHA256, Macaroon-style attenuation chain)
- [x] Intent extractor client + intent check (second of four)
- [x] Embedded OPA policy evaluation (third of four)
- [x] Budget enforcement (Redis-backed, fourth of four; taint TBD)
- [x] Audit log emission (OCSF-lite JSON to stdout)
- [ ] Upstream proxying for `tools/list`, `initialize`, `ping`
- [ ] Helm chart

## Development

```sh
make fmt    # gofmt -s -w .
make vet    # go vet ./...
make test   # go test -race ./...
make tidy   # go mod tidy
```

## Contributing

The gateway is Apache 2.0 and accepts community contributions. A formal
CLA process will be set up before the first external PR — for now please
open an issue to discuss any non-trivial change.
