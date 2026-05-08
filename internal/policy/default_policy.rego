# Default IntentGate policy. Edit a copy of this file and point the
# gateway at it via INTENTGATE_POLICY_FILE to customize.
#
# Required entry point: data.intentgate.policy.decision must resolve to
# {"allow": <bool>, "reason": <string>}. The gateway treats a missing
# decision as deny (fail-closed).
#
# Input shape (built by the gateway, passed in as `input`):
#
#   tool         string
#   args         object   (may be empty; tool-specific shape)
#   agent_id     string   (from the verified capability token)
#   session_id   string   (optional)
#   intent       object   (optional; populated when an X-Intent-Prompt
#                          header was supplied and the extractor ran)
#     .summary, .allowed_tools, .forbidden_tools, .confidence
#   capability   object
#     .subject, .issuer

package intentgate.policy

# Enables modern Rego syntax: `if`, `in`, `every`, `contains` built-in.
# Required by OPA 1.x when using these keywords.
import rego.v1

# Fail closed: if no later rule matches, the gateway denies the call.
default decision := {
	"allow": false,
	"reason": "no policy rule matched (default deny)",
}

# Allow any tool whose name starts with read_*. Reads are rarely
# destructive on their own; further restrictions can be expressed via
# capability tokens or the intent extractor.
decision := {"allow": true, "reason": "read-only tool"} if {
	startswith(input.tool, "read_")
}

# Routine writes that are bounded in blast radius — these are the tools
# IntentGate's reference deployment expects to see often.
decision := {"allow": true, "reason": "routine write tool"} if {
	input.tool in {"record_in_ledger", "verify_vendor", "fetch_company_data", "web_search"}
}

# Money-moving tools split on a numeric threshold. The gateway populates
# input.args from the agent's tool-call payload, so amount_eur arrives
# here as whatever the agent sent. Customers will tune this number; the
# canonical version of this rule lives in their org's policy file.
decision := {"allow": true, "reason": "transfer at or below 10000 EUR threshold"} if {
	input.tool == "transfer_funds"
	to_number(input.args.amount_eur) <= 10000
}

decision := {"allow": false, "reason": "transfer above 10000 EUR threshold"} if {
	input.tool == "transfer_funds"
	to_number(input.args.amount_eur) > 10000
}

# Categorical hard blocks — destructive operations that should never be
# permitted via this gateway. Customer policies may keep, expand, or
# remove this list.
decision := {"allow": false, "reason": "destructive tool blocked by policy"} if {
	input.tool in {"delete", "drop_table", "factory_reset", "purge_audit"}
}
