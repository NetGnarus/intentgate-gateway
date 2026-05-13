# Quickstart — gateway running in 5 minutes

This guide gets a minimal IntentGate gateway running on your laptop in about five minutes, backed by in-memory stores. No Postgres, no Redis, no Kubernetes — just `docker run` and a curl. After this you'll have a working gateway accepting capability tokens and making decisions you can audit.

The setup here is dev-mode: in-memory stores lose state on restart, the intent extractor is disabled, no metrics exposed. It's the right shape for "I want to see what this thing does." When you're ready for production, follow the deployment runbook ([request via /contact](https://intentgate.app/contact)) or the [Helm chart](https://github.com/NetGnarus/intentgate-helm) for the multi-replica path.

## Prerequisites

- Docker — `docker --version` should return 20.10+. macOS users: Docker Desktop. Linux: docker engine + the compose plugin (`apt-get install docker-compose-plugin` on recent Ubuntu).
- `openssl` for generating secrets. Pre-installed on macOS and most Linux distros.
- `curl` for hitting the gateway. Pre-installed on macOS and most Linux distros.
- `jq` for readable JSON output. `brew install jq` or `apt-get install jq`.

## Step 1 — Generate two secrets

The gateway needs two secrets at boot: a master key for signing capability tokens, and an admin token gating `/v1/admin/*` endpoints.

```sh
MASTER_KEY=$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=')
ADMIN_TOKEN=$(openssl rand -hex 32)

echo "Master key: $MASTER_KEY"
echo "Admin token: $ADMIN_TOKEN"
```

Save the admin token somewhere — you'll need it to mint capability tokens in step 3 and again in [Guide 02](./02-first-policy.md). The master key only matters as long as you want tokens to keep working; lose it and any tokens you've issued become invalid.

## Step 2 — Run the gateway

One docker command, in-memory mode:

```sh
docker run -d --name intentgate-gateway \
  -p 8080:8080 \
  -e INTENTGATE_ADDR=:8080 \
  -e INTENTGATE_MASTER_KEY="$MASTER_KEY" \
  -e INTENTGATE_ADMIN_TOKEN="$ADMIN_TOKEN" \
  -e INTENTGATE_REQUIRE_CAPABILITY=true \
  ghcr.io/netgnarus/intentgate-gateway:1.6.1
```

Verify it's alive:

```sh
curl -s http://localhost:8080/healthz
```

Returns `{"status":"ok","version":"..."}`. If you get a connection error, check `docker logs intentgate-gateway` — the most common cause is the master key not being set correctly.

## Step 3 — Mint your first capability token

Capability tokens are HMAC-signed bearers that an agent presents on every tool call. Each token has caveats — the most common being a *tool whitelist* — that the gateway verifies before any policy runs. An agent with a token scoped to `read_invoice` cannot call `transfer_funds`, even if your policy would allow it.

Mint one:

```sh
TOKEN=$(curl -sS -X POST http://localhost:8080/v1/admin/mint \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":    "agent-readonly",
    "tools":      ["read_invoice"],
    "ttl_seconds": 3600,
    "max_calls":   100
  }' | jq -r '.token')

echo "Token: $TOKEN" | head -c 100; echo "..."
```

The token is a base64url-encoded HMAC chain. It's safe to pass through logs and process arguments (it's signed, not encrypted, but it can only be used until it's revoked or expires).

## Step 4 — Make a tool call

Without an upstream tool server configured, the gateway returns a stub allow on calls that pass every check. That's enough to verify the pipeline works:

```sh
curl -s -X POST http://localhost:8080/v1/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "read_invoice",
      "arguments": {"id": "INV-1001"}
    }
  }' | jq
```

You should see a JSON-RPC `result` object with a stub message confirming the call was authorized. Try changing `"name": "read_invoice"` to `"name": "transfer_funds"` — your token doesn't authorize that tool, so you'll get a JSON-RPC error with `code: -32010` and message `capability check failed`. That's the first of the four controls firing.

For a tool call that returns *real* data instead of a stub, point the gateway at an upstream tool server with `INTENTGATE_UPSTREAM_URL=<your-server>`. The companion `demo-toolserver` in [`examples/demo-toolserver/`](../examples/demo-toolserver/) is a minimal HTTP-JSON-RPC server you can run locally for end-to-end smoke tests.

## Step 5 — Clean up

When you're done playing:

```sh
docker stop intentgate-gateway
docker rm intentgate-gateway
```

## What's next

- **Add a policy.** Right now the gateway runs the bundled default policy (allow read_*, allow some routine writes, block destructive operations, escalate transfer_funds above €10K). [Guide 02](./02-first-policy.md) shows you how to override it with your own Rego.
- **Wire an agent.** Curl is fine for smoke tests; production agents use the SDKs. [Guide 03](./03-first-agent.md) walks through the Python SDK.
- **Query audit.** Every decision (allow or block) emitted one audit event. [Guide 04](./04-audit-verify.md) shows you how to query them and verify the chain.

## When to graduate to production

The single-container, in-memory setup above is fine for development. Before you put IntentGate in front of real agents handling real data, you'll want:

- **Postgres for persistence.** Audit events, approval queue, policy drafts. Set `INTENTGATE_POSTGRES_URL`, `INTENTGATE_AUDIT_PERSIST=true`, `INTENTGATE_APPROVALS_BACKEND=postgres`, `INTENTGATE_POLICY_STORE=postgres`.
- **Redis for budget.** Per-token counters need to be shared across replicas. Set `INTENTGATE_REDIS_URL`.
- **The extractor service** for real intent matching. Otherwise the intent check is bypassed.
- **SIEM forwarding** if you have Splunk / Datadog / Sentinel — see the README's SIEM section.
- **TLS termination** in front (Caddy, nginx, an ingress controller).
- **High availability** — at least two gateway replicas behind a load balancer.

The [Helm chart](https://github.com/NetGnarus/intentgate-helm) wraps all of that into one `helm install`.
