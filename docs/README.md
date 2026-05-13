# IntentGate Docs

End-user documentation for platform engineers, security engineers, and developers integrating IntentGate into their AI agent stack. Each guide is focused on a single milestone you'll hit when bringing the gateway into your environment.

If you're new here, start with **[01 — Quickstart](./01-quickstart.md)**. It gets a gateway running locally in five minutes against an in-memory backend so you can see the four-control pipeline fire on a real request.

| # | Guide | Audience | Time |
|---|-------|----------|------|
| 01 | [Quickstart — gateway running in 5 minutes](./01-quickstart.md) | Anyone evaluating IntentGate | 5 min |
| 02 | [Your first Rego policy](./02-first-policy.md) | Platform / security engineer | 15 min |
| 03 | [Wire your first agent (Python SDK)](./03-first-agent.md) | Application developer | 15 min |
| 04 | [Querying audit and verifying the chain](./04-audit-verify.md) | SOC analyst / compliance | 10 min |

Beyond these four guides:

- **The gateway README** ([../README.md](../README.md)) — full feature list, architecture, contributor / build-from-source instructions.
- **The deployment runbook** — 23-page operational guide covering production deployment (Helm), day-2 operations (monitoring, scaling, backup/restore), and incident playbooks. Available via `/contact` on [intentgate.app](https://intentgate.app/contact).
- **API reference** — every `/v1/admin/*` endpoint with request/response shapes. Coming to `docs.intentgate.app` as the docs site comes online; in the meantime the source of truth is [`internal/handlers/`](../internal/handlers/) in this repo.
- **The companion repos:**
  - [`intentgate-helm`](https://github.com/NetGnarus/intentgate-helm) — Kubernetes chart deploying gateway + extractor + Postgres.
  - [`intentgate-extractor`](https://github.com/NetGnarus/intentgate-extractor) — the intent extractor service (FastAPI + Claude Haiku, with offline stub).
  - [`intentgate-sdk-python`](https://github.com/NetGnarus/intentgate-sdk-python) — Python SDK.
  - [`intentgate-sdk-typescript`](https://github.com/NetGnarus/intentgate-sdk-typescript) — TypeScript SDK.

## The four controls

Every page assumes you've read this:

IntentGate evaluates each tool call through four independent checks before it forwards to the upstream tool server. Each check has its own failure mode and its own JSON-RPC error code so audit downstream can distinguish them.

1. **Capability** — Did the agent present a valid HMAC-signed token whose caveats permit *this specific tool*? Failure: `-32010`. Defends against stolen credentials and over-broad tokens.
2. **Intent** — Does the agent's declared purpose (the `X-Intent-Prompt` header, run through the intent extractor) include this tool in its `allowed_tools` list? Failure: `-32011`. Defends against prompt injection — an attacker can't change the user's intent into one that suddenly needs `transfer_funds`.
3. **Policy** — Does the loaded Rego policy say allow / block / escalate for this call given the agent, tool, args, and intent? Failure: `-32012`. Defends against over-broad permissions — your policy can constrain what's allowed even when capability and intent already passed.
4. **Budget** — Is the agent's per-token call counter still under its `max_calls` cap? Failure: `-32013`. Defends against runaway loops and metering excess.

Every decision (allow at any stage, block at any stage, escalate from policy to human approval) emits one audit event into a per-tenant cryptographic hash chain. That chain is what [Guide 04](./04-audit-verify.md) shows you how to query and verify.

For a longer essay framing the threat model these controls address, read [The four-control bypass](https://intentgate.app/why-intentgate) on the website.
