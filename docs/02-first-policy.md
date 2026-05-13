# Your first Rego policy

This guide walks you through writing a Rego policy that constrains what your agents can do, pushing it into a running IntentGate gateway, and watching it fire. By the end you'll understand how the policy check fits into the four-control pipeline and have a working template you can customize.

Prerequisite: a gateway running per [Guide 01](./01-quickstart.md). The example commands assume `$ADMIN_TOKEN` and `$TOKEN` are set as in that guide.

## What the policy check actually does

The policy check is the third of four controls. It runs *after* capability and intent have already passed, *before* budget. The gateway evaluates the loaded Rego policy against the request and reads back a decision object:

```rego
{"allow": true,  "reason": "..."}                      # let it through
{"allow": false, "reason": "..."}                      # block
{"allow": false, "escalate": true, "reason": "..."}    # pause for human approval
```

`escalate` is the most interesting outcome — the gateway suspends the call, writes a row into the approval queue (visible in console-pro's `/approvals` page), and waits for an admin to approve or reject. The agent's HTTP request hangs until a decision is made or the configured timeout fires.

The policy receives an `input` object the gateway populates:

```rego
input.tool            # string — the tool the agent is calling
input.args            # object — tool-specific arguments
input.agent_id        # string — from the verified capability token
input.session_id      # string — optional
input.intent          # object — populated when X-Intent-Prompt header was supplied
  .summary
  .allowed_tools
  .forbidden_tools
  .confidence
input.capability      # object
  .subject
  .issuer
  .step_up_at         # unix seconds — set when token was minted with step_up:true
```

Required entry point: `data.intentgate.policy.decision`. A missing decision is treated as block (fail-closed).

## Writing a baseline policy

Save the following as `baseline.rego`:

```rego
# baseline.rego — IntentGate starter policy.
#
# Required entry point: data.intentgate.policy.decision must resolve
# to {"allow": <bool>, "reason": <string>, "escalate": <bool?>}.

package intentgate.policy

import rego.v1

# Fail-closed default. Any call not matched by a later rule is denied.
default decision := {
    "allow": false,
    "reason": "no policy rule matched (default deny)",
}

# Read-only tools are allow-by-default. read_* is a naming convention
# the gateway can't enforce on its own — your tool authors get to say
# what's a read. Pair this with capability tokens that whitelist
# specific tools to prevent an attacker from naming a write `read_*`.
decision := {"allow": true, "reason": "read-only tool"} if {
    startswith(input.tool, "read_")
}

# Money-moving tools split on a numeric threshold. Below the line
# proceeds; above the line pauses for a human. The €5,000 number is
# illustrative — tune to your blast-radius tolerance.
decision := {
    "allow": true,
    "reason": "transfer at or below 5000 EUR threshold",
} if {
    input.tool == "transfer_funds"
    to_number(input.args.amount_eur) < 5000
}

decision := {
    "allow": false,
    "escalate": true,
    "reason": "transfer at or above 5000 EUR threshold — admin approval required",
} if {
    input.tool == "transfer_funds"
    to_number(input.args.amount_eur) >= 5000
}

# Categorical hard blocks. These are the tools you want to refuse
# regardless of caller, intent, or amount.
decision := {
    "allow": false,
    "reason": "destructive tool blocked by policy",
} if {
    input.tool in {"delete", "drop_table", "factory_reset", "purge_audit"}
}
```

## Push it into the gateway

The gateway has two ways to load policy: a file mount via `INTENTGATE_POLICY_FILE`, or a live API push that survives restarts when backed by Postgres. The API path is the operational one — you can update policy without restarting the gateway.

For the API path, set `INTENTGATE_POLICY_STORE=memory` (or `postgres` for persistence) when starting the gateway. The quickstart didn't, so either restart with that env var or just use the file mount for now (`docker run ... -v $(pwd)/baseline.rego:/policy.rego -e INTENTGATE_POLICY_FILE=/policy.rego`).

Assuming `INTENTGATE_POLICY_STORE=memory`, push the policy:

```sh
DRAFT_ID=$(curl -sS -X POST http://localhost:8080/v1/admin/policies/drafts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg name 'baseline' \
    --arg description 'starter policy from docs/02' \
    --rawfile rego baseline.rego \
    --arg created_by 'platform' \
    '{name:$name, description:$description, rego_source:$rego, created_by:$created_by}')" \
  | jq -r '.id')

echo "Draft ID: $DRAFT_ID"
```

The gateway compiles the Rego on the way in — known-bad syntax returns 400 with OPA's parser output verbatim, which is what console-pro's editor surfaces. If the draft was created successfully, promote it to active:

```sh
curl -sS -X POST http://localhost:8080/v1/admin/policies/active \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"draft_id\": \"$DRAFT_ID\"}" | jq
```

Promote is atomic per tenant — the gateway hot-swaps the compiled engine in-place and the next request uses the new policy. No restart, no dropped connections.

## Test it

You need a token that can call `transfer_funds`. Re-mint with a broader scope:

```sh
BROAD_TOKEN=$(curl -sS -X POST http://localhost:8080/v1/admin/mint \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":    "agent-finance",
    "tools":      ["read_invoice", "transfer_funds"],
    "ttl_seconds": 3600
  }' | jq -r '.token')
```

**A transfer below the threshold — should allow:**

```sh
curl -sS -X POST http://localhost:8080/v1/mcp \
  -H "Authorization: Bearer $BROAD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {
      "name": "transfer_funds",
      "arguments": {"from_account":"A", "to_account":"B", "amount_eur": 4900}
    }
  }' | jq
```

Returns a `result` object (allow). The audit log will show `decision=allow`, `reason="transfer at or below 5000 EUR threshold"`.

**A transfer at the threshold — should escalate:**

```sh
curl -sS -X POST http://localhost:8080/v1/mcp \
  -H "Authorization: Bearer $BROAD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {
      "name": "transfer_funds",
      "arguments": {"from_account":"A", "to_account":"B", "amount_eur": 50000}
    }
  }' | jq
```

The request hangs — the gateway is waiting for a human to approve. If you have `INTENTGATE_APPROVALS_BACKEND=postgres` set, you can approve via:

```sh
curl -sS http://localhost:8080/v1/admin/approvals \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq

# Get the pending_id from the response, then:
curl -sS -X POST http://localhost:8080/v1/admin/approvals/<id>/decide \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"decision": "approve", "decided_by": "you@example.com"}'
```

The hanging curl from above immediately returns the upstream result.

**A destructive tool — should block:**

```sh
curl -sS -X POST http://localhost:8080/v1/mcp \
  -H "Authorization: Bearer $BROAD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "delete", "arguments": {"id": "anything"}}
  }' | jq
```

Returns a JSON-RPC error with `code: -32012` and message `policy check failed`. The audit log carries `decision=block`, `reason="destructive tool blocked by policy"`.

## Common patterns to copy

**Time-of-day restriction** — block writes outside business hours:

```rego
decision := {
    "allow": false,
    "reason": "writes outside business hours",
} if {
    not startswith(input.tool, "read_")
    hour := time.clock(time.now_ns())[0]
    hour < 9
}

decision := {
    "allow": false,
    "reason": "writes outside business hours",
} if {
    not startswith(input.tool, "read_")
    hour := time.clock(time.now_ns())[0]
    hour >= 18
}
```

**Per-agent overrides** — give one specific agent extended permissions:

```rego
decision := {"allow": true, "reason": "trusted batch processor"} if {
    input.agent_id == "agent-batch-processor"
    input.tool in {"read_invoice", "list_invoices", "record_in_ledger"}
}
```

**Step-up required** — refuse high-risk operations unless the token carries a recent fresh-factor:

```rego
decision := {"allow": false, "escalate": true, "reason": "step-up required"} if {
    input.tool == "transfer_funds"
    to_number(input.args.amount_eur) >= 5000
    now := time.now_ns() / 1000000000
    step_up_age := now - input.capability.step_up_at
    step_up_age > 300
}
```

**Intent-aware constraint** — only allow if the intent extractor agreed:

```rego
decision := {"allow": false, "reason": "tool not in intent allowlist"} if {
    not (input.tool in input.intent.allowed_tools)
}
```

## Dry-run before promoting

When you change a policy in production, you don't want to discover the rule has a regression in real traffic. The gateway has a dry-run endpoint that evaluates candidate policy against a sample of recent audit events and reports the differential:

```sh
curl -sS -X POST http://localhost:8080/v1/admin/policies/dry-run \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --rawfile rego baseline-v2.rego \
    '{rego_source:$rego, sample_size: 1000}')" | jq
```

Returns counts of `unchanged / changed_allow_to_block / changed_block_to_allow / changed_to_escalate` so you can spot rule regressions before they hit production. Console-pro's policy editor wraps this with a side-by-side diff view.

## What's next

- **Tag your policy** in source control. Customers running production traffic usually keep their Rego in a git repo and push via CI on merge to main. The console-pro `/policies` page shows current active + draft policies with provenance (who pushed, when, prior policy).
- **Wire an agent** to actually exercise the policy. [Guide 03](./03-first-agent.md) covers the Python SDK.
- **Watch decisions** in the audit log to learn which rules fire most. [Guide 04](./04-audit-verify.md).
