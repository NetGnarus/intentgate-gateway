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

`v0.1.0-dev` — **HTTP + MCP framing + capability check.**

The server boots and accepts requests on three endpoints:

- `GET  /healthz` — liveness probe.
- `POST /v1/tool-call` — simple flat JSON shape, kept for ad-hoc curl testing.
- `POST /v1/mcp` — JSON-RPC 2.0 / Model Context Protocol. Canonical contract for MCP-speaking clients. Verifies a capability token (Bearer, Macaroon-style HMAC chain) when present and evaluates its caveats against the requested tool.

Three of four checks remain (intent, policy, budget). When all four are
in place, every well-formed call is gated by the full pipeline; for now,
calls that pass capability are allowed with a stub reason.

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

## v0.1 roadmap

- [x] HTTP skeleton, `/v1/tool-call` and `/healthz`
- [x] MCP / JSON-RPC request parsing (`/v1/mcp`, `tools/call` only)
- [x] Capability tokens (HMAC-SHA256, Macaroon-style attenuation chain)
- [ ] Intent extractor client (calls the Python service)
- [ ] Embedded OPA policy evaluation
- [ ] Budget and taint enforcement (Redis-backed)
- [ ] Audit log emission (OCSF / ECS)
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
