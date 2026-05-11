# IntentGate demo tool server

A minimal HTTP-JSON-RPC service that the IntentGate gateway can forward to as `INTENTGATE_UPSTREAM_URL`, so end-to-end demos return real tool results instead of the gateway's `"stub: no upstream configured"` placeholder.

**Not for production use.** This server exists to make IntentGate's verify scripts and pitch demos non-stubby. Production tool servers would talk to actual systems (databases, APIs, file systems); the three tools here return synthetic fixture data.

## What's in the box

Three mock tools, picked to map onto the standard IntentGate pitch scenarios:

| Tool | What it does | Why it's here |
| --- | --- | --- |
| `read_invoice(id)` | Returns a synthetic invoice by id (with a non-404 fallback). | The default "agent does a read" tool in every verify script. |
| `list_customers(limit)` | Returns up to N customers from a fixed fixture list. | Demos that want to exercise "policy blocks bulk reads as data-exfil pattern." |
| `transfer_funds(from, to, amount_eur)` | Returns a `"would transfer"` acknowledgement. No actual banking. | The standard "escalate above 5,000 EUR" pitch demo target. |

## Protocol

JSON-RPC 2.0 over HTTP `POST /`. Two methods: `tools/list` and `tools/call`. Matches the shape the IntentGate gateway forwards from its `/v1/mcp` endpoint, so wiring it up is a single env var.

## Run locally

```sh
# From this directory.
pip install .
uvicorn app.main:app --host 0.0.0.0 --port 8090

# In another shell:
curl -s -X POST http://localhost:8090/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"id":"INV-1001"}}}' \
  | jq
```

## Run via Docker

```sh
docker build -t intentgate-demo-toolserver:0.1.0 .
docker run --rm -p 8090:8090 intentgate-demo-toolserver:0.1.0
```

## Wire into the IntentGate gateway

The chart-managed path (recommended for end-to-end demos):

```sh
helm upgrade ig oci://ghcr.io/netgnarus/charts/intentgate -n intentgate \
  --reuse-values \
  --set demoUpstream.enabled=true
```

That deploys the demo toolserver alongside the gateway and wires the gateway's `INTENTGATE_UPSTREAM_URL` to point at it.

The local path (for kicking the tires):

```sh
# In one shell: run the toolserver
uvicorn app.main:app --host 0.0.0.0 --port 8090 &

# In another: run the gateway against it
docker run --rm -p 8080:8080 \
  -e INTENTGATE_UPSTREAM_URL=http://host.docker.internal:8090 \
  ghcr.io/netgnarus/intentgate-gateway:1.5.1
```

## What this isn't

- Not an MCP server in the strict protocol-conformance sense. Real MCP servers speak stdio or SSE; this one speaks plain HTTP-JSON-RPC because that's what the gateway forwards. If you have a real MCP server, point the gateway at an HTTP-bridged copy of it.
- Not authenticated. The gateway authenticates the agent via capability tokens upstream of this server; nothing this server returns is sensitive in any deployment shape.
- Not stateful. There's no database. Restart it and you get the same fixture data.

## License

Apache 2.0.
