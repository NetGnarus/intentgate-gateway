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

`v0.1.0-dev` — **HTTP + MCP framing.**

The server boots and accepts requests on three endpoints:

- `GET  /healthz` — liveness probe.
- `POST /v1/tool-call` — simple flat JSON shape, kept for ad-hoc curl testing.
- `POST /v1/mcp` — JSON-RPC 2.0 / Model Context Protocol. Canonical contract for MCP-speaking clients.

Both tool-call endpoints currently return a stubbed `"allow"` decision —
the four-check pipeline (capability, intent, policy, budget) is not
wired up yet. That lands in session 3+.

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
cmd/gateway/        # main package, entrypoint, graceful shutdown
internal/server/    # HTTP server, middleware (request logger, panic recovery)
internal/handlers/  # /healthz, /v1/tool-call, /v1/mcp handlers
internal/mcp/       # JSON-RPC 2.0 envelope, MCP method types, error codes
pkg/                # reserved for public packages (future SDK integration types)
Dockerfile          # multi-stage: build in golang:1.22-alpine, run in distroless
Makefile            # build / run / test / docker / smoke targets
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

| Env var             | Default | Description                  |
| ------------------- | ------- | ---------------------------- |
| `INTENTGATE_ADDR`   | `:8080` | HTTP listen address.         |

More configuration arrives with the policy engine, intent extractor client,
and storage layers.

## v0.1 roadmap

- [x] HTTP skeleton, `/v1/tool-call` and `/healthz`
- [x] MCP / JSON-RPC request parsing (`/v1/mcp`, `tools/call` only)
- [ ] Capability tokens (HMAC-SHA256, attenuation chain)
- [ ] Embedded OPA policy evaluation
- [ ] Intent extractor client (calls the Python service)
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
