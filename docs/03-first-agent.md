# Wire your first agent (Python SDK)

This guide takes you from a freshly-installed Python SDK to an agent calling tools through the IntentGate gateway and handling each of the four denial modes as a typed Python exception. The path is roughly 15 minutes.

Prerequisite: a gateway running per [Guide 01](./01-quickstart.md). The example commands assume `$ADMIN_TOKEN` is set as in that guide. Python 3.10 or later required.

## Install

```sh
pip install intentgate
```

The package is on PyPI. If you want to install the development tip:

```sh
pip install git+https://github.com/NetGnarus/intentgate-sdk-python.git
```

There's a [TypeScript SDK](https://github.com/NetGnarus/intentgate-sdk-typescript) with byte-compatible token semantics — same patterns, same exception hierarchy under different names. If your agent is in Node.js, install `@netgnarus/intentgate` instead and follow the same flow.

## Mint a token

The SDK doesn't talk to admin endpoints — that's the operator's job. Mint a token out-of-band using the same `curl` call from Guide 01:

```sh
TOKEN=$(curl -sS -X POST http://localhost:8080/v1/admin/mint \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":    "agent-finance",
    "tools":      ["read_invoice", "transfer_funds"],
    "ttl_seconds": 3600,
    "max_calls":   100
  }' | jq -r '.token')

export INTENTGATE_TOKEN="$TOKEN"
```

In production you'd issue tokens through your control plane (the console-pro UI, the `igctl` CLI, or your own automation against the admin API). Tokens are bound to a subject (your agent's identity), expire, and carry caveats that constrain what they can do — the SDK never touches any of this; the gateway enforces it.

## Three-line agent

```python
import os
from intentgate import Gateway

gw = Gateway(url="http://localhost:8080", token=os.environ["INTENTGATE_TOKEN"])
result = gw.tool_call(
    "read_invoice",
    arguments={"id": "INV-1001"},
    intent_prompt="Process today's accounts payable invoices",
)
print(result.data)
```

Run it. If the gateway is alive and your token is valid, you'll see the stub allow response (or, if `INTENTGATE_UPSTREAM_URL` is set, the real upstream's result). That's the happy path — capability check passed (token is signed, subject matches), intent check passed (the prompt's allowed_tools includes `read_invoice`), policy check passed (read tools are allowed by the baseline), budget check passed (you have 99 calls left).

The `result.data` field carries whatever the upstream tool server returned. The `result.metadata` field carries gateway-side telemetry — latency, decision reason, policy rule that fired, etc.

## Handling denials

Every blocked call raises a typed exception. The class tells you which check fired:

```python
from intentgate import Gateway, CapabilityError, IntentError, PolicyError, BudgetError

try:
    result = gw.tool_call(
        "transfer_funds",
        arguments={"from_account": "A", "to_account": "B", "amount_eur": 50000},
        intent_prompt="Pay invoice INV-1002 to vendor G42",
    )
except CapabilityError as e:
    # Token doesn't grant this tool, or token is expired/revoked.
    # Surface to the user: "you don't have permission for this action."
    print(f"capability: {e.message}")

except IntentError as e:
    # The intent extracted from the prompt doesn't include this tool.
    # Likely a prompt-injection attempt or a genuinely misaligned request.
    # Surface: "this doesn't seem related to what you asked for."
    print(f"intent: {e.message}")

except PolicyError as e:
    # Rego policy denied. The reason carries the rule's explanation,
    # which is operator-readable — safe to surface, or log + show a
    # generic "rejected by policy" depending on your UI.
    print(f"policy: {e.message}")
    if e.escalated:
        # Special sub-case: policy returned {escalate: true}. The call
        # is pending in the approval queue; an admin needs to decide.
        # Your agent should treat this as "wait" rather than "fail."
        print(f"  pending approval: {e.pending_id}")

except BudgetError as e:
    # max_calls exhausted. Mint a fresh token (with operator approval)
    # or back off — this is your circuit breaker firing.
    print(f"budget: {e.message}")
```

You can catch the base class `IntentGateError` if your agent doesn't care which check fired:

```python
from intentgate import IntentGateError

try:
    result = gw.tool_call(...)
except IntentGateError as e:
    log.warning("blocked: %s", e)
    # show generic error to user, return to LLM for retry, etc.
```

## Idiomatic agent patterns

**LLM loop with structured error feedback.** When the gateway blocks a call, feed the reason back into the LLM so it can self-correct rather than retry blindly:

```python
from intentgate import Gateway, IntentGateError

gw = Gateway(url=GATEWAY_URL, token=AGENT_TOKEN)
user_prompt = input("What can I do for you? ")

messages = [{"role": "user", "content": user_prompt}]
while True:
    response = llm.chat(messages, tools=AVAILABLE_TOOLS)
    if not response.tool_calls:
        print(response.content)
        break

    for call in response.tool_calls:
        try:
            result = gw.tool_call(
                call.name,
                arguments=call.arguments,
                intent_prompt=user_prompt,  # the SAME user prompt, every call
            )
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps(result.data),
            })
        except IntentGateError as e:
            # Surface the rejection reason to the LLM as a tool error
            # so it can adjust strategy or surface the limit to the user.
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps({
                    "error": "authorization_denied",
                    "reason": e.message,
                }),
            })
```

The `intent_prompt` should always be the **original user prompt** — not the LLM's per-call reasoning, not a synthesized intent. The intent check is exactly the defense against prompt injection: an attacker who can manipulate the LLM into asking for `transfer_funds` cannot manipulate the user's original prompt, so the extractor's `allowed_tools` list stays grounded in what the user actually wanted.

**Token attenuation for sub-agents.** If your agent spawns a sub-agent (e.g., a planner that delegates to a worker), the sub-agent's token should be *more constrained* than the planner's. The SDK has an `attenuate` function that adds caveats without contacting the gateway — the new token is mathematically a subset of the original:

```python
from intentgate import attenuate

# Planner has a broad token. Worker only needs read_invoice.
worker_token = attenuate(
    planner_token,
    tool_allow=["read_invoice"],
    max_calls=10,
    not_before=int(time.time()),
    expires_at=int(time.time()) + 300,  # 5-minute window
)
worker_gw = Gateway(url=GATEWAY_URL, token=worker_token)
```

The gateway validates the entire HMAC chain on each call, so attenuated tokens can't grant more than the parent ever had.

## Run it against the lab

If you want a non-stub upstream that returns real fixture data — invoices, customers, transfer acks — point your gateway at the demo toolserver in [`examples/demo-toolserver/`](../examples/demo-toolserver/). The toolserver exposes three mock tools (`read_invoice`, `list_customers`, `transfer_funds`) with synthetic data. Run it on `:8090` and set `INTENTGATE_UPSTREAM_URL=http://localhost:8090` on the gateway. Your `read_invoice` calls now return real-looking invoice records you can iterate on policy against.

## What's next

- **Audit your calls.** Every `tool_call` (allow or block) emitted one audit event. [Guide 04](./04-audit-verify.md) shows how to query the chain.
- **Tune your policy.** As you watch real agent traffic, you'll see calls that should have been blocked but weren't (or vice versa). [Guide 02](./02-first-policy.md) walks through writing and dry-running Rego changes.
- **Hook your control plane.** The SDK's exception classes match the gateway's audit event categories — if you wire `PolicyError` (with `escalated=True`) to your existing approval workflow, you get the human-in-the-loop story for free without your agent code ever knowing about the approval queue.

Full SDK reference (every method, every parameter, async variants, advanced patterns) lives in the [SDK README](https://github.com/NetGnarus/intentgate-sdk-python).
