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

`v0.1.0-dev` — **HTTP skeleton only.**

The server boots, accepts JSON tool-call requests on `POST /v1/tool-call`,
and returns a fixed `"allow"` decision. Health probe at `GET /healthz`.

The four-check pipeline is **not implemented yet** — every well-formed call
is allowed with a stub reason. That is by design for this session; the
pipeline lands in subsequent sessions.

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

In another shell, smoke-test it:

```sh
make smoke
```

That sends a `GET /healthz` and a `POST /v1/tool-call` with a sample payload
and prints the JSON responses. Equivalent curl by hand:

```sh
curl -s http://localhost:8080/healthz

curl -sX POST http://localhost:8080/v1/tool-call \
  -H 'Content-Type: application/json' \
  -d '{
        "tool":      "read_invoice",
        "args":      {"id": "123"},
        "agent_id":  "finance-copilot-v3",
        "session_id":"sess_abc"
      }'
```

Expected response:

```json
{
  "decision": "allow",
  "reason":   "stub: pipeline not implemented",
  "latency_ms": 0
}
```

## Project layout

```
cmd/gateway/        # main package, entrypoint, graceful shutdown
internal/server/    # HTTP server, middleware (request logger, panic recovery)
internal/handlers/  # /healthz and /v1/tool-call handlers
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
- [ ] MCP / JSON-RPC request parsing
- [ ] Capability tokens (HMAC-SHA256, attenuation chain)
- [ ] Embedded OPA policy evaluation
- [ ] Intent extractor client (calls the Python service)
- [ ] Budget and taint enforcement (Redis-backed)
- [ ] Audit log emission (OCSF / ECS)
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
