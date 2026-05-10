#!/usr/bin/env bash
#
# IntentGate gateway benchmark harness.
#
# Mints a long-TTL test token via the admin API, then sweeps a range
# of request rates against /v1/mcp tools/call with vegeta. After each
# rate, scrapes /metrics so we can break latency down by check stage.
# Writes a self-contained BENCHMARKS.md you can paste into the repo.
#
# This is a *macro* benchmark: it measures the full request path —
# decode → verify → revocation lookup → policy → audit → response —
# end-to-end, against a real running gateway. Per-handler micro
# benchmarks live in Go test files; this one is what you cite when a
# design partner asks "can it keep up?".
#
# Prerequisites:
#   brew install vegeta jq
#   kubectl -n intentgate port-forward svc/ig-intentgate-gateway 8080:8080 &
#   export ADMIN_TOKEN=super-secret-token   # or whatever your superadmin is
#
# Usage:
#   ./scripts/bench.sh                # default sweep
#   DURATION=10s RATES="100 500" ./scripts/bench.sh   # quick run
#
# Output:
#   BENCHMARKS.md (in repo root) — overwritten on each run
#   /tmp/intentgate-bench/*.json    — raw vegeta reports per rate
#

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
DURATION="${DURATION:-30s}"
# Space-separated. Sweep low to high; the script stops early if the
# gateway saturates (success rate drops below 99%) so we don't waste
# minutes pounding a saturated process.
RATES="${RATES:-100 500 1000 2000 4000}"
PROFILE_NAME="${PROFILE_NAME:-as-deployed}"

OUT_DIR="/tmp/intentgate-bench"
REPORT_MD="${REPORT_MD:-BENCHMARKS.md}"

# ----------------------------------------------------------------------
# Pre-flight
# ----------------------------------------------------------------------

if ! command -v vegeta >/dev/null; then
  echo "error: vegeta not found. install with: brew install vegeta" >&2
  exit 1
fi
if ! command -v jq >/dev/null; then
  echo "error: jq not found. install with: brew install jq" >&2
  exit 1
fi
if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "error: ADMIN_TOKEN env var is required" >&2
  echo "  export ADMIN_TOKEN=<your gateway superadmin token>" >&2
  exit 1
fi

if ! curl -sf "$GATEWAY_URL/healthz" >/dev/null; then
  echo "error: gateway not reachable at $GATEWAY_URL" >&2
  echo "  start a port-forward first:" >&2
  echo "    kubectl -n intentgate port-forward svc/ig-intentgate-gateway 8080:8080 &" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.json "$OUT_DIR"/*.bin

# ----------------------------------------------------------------------
# Capture environment
# ----------------------------------------------------------------------

GATEWAY_VERSION=$(curl -sf "$GATEWAY_URL/healthz" | jq -r '.version // "unknown"')
DATESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)
HOST_CPU_COUNT=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
HOST_DESC="$HOST_OS/$HOST_ARCH, $HOST_CPU_COUNT cores"

echo "==> gateway version: $GATEWAY_VERSION"
echo "==> host: $HOST_DESC"
echo "==> profile: $PROFILE_NAME"
echo "==> rates: $RATES"
echo "==> duration per rate: $DURATION"
echo

# ----------------------------------------------------------------------
# Mint a long-TTL benchmark token
# ----------------------------------------------------------------------

# 30-minute TTL is well over the longest sweep, with a generous max-call
# budget so the budget check (when enabled) doesn't deny mid-attack.
MINT_BODY='{
  "subject":"bench-agent",
  "ttl_seconds":1800,
  "tools":["read_invoice"],
  "max_calls":10000000
}'

MINT_RESP=$(curl -sf -X POST "$GATEWAY_URL/v1/admin/mint" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$MINT_BODY")

TOKEN=$(echo "$MINT_RESP" | jq -r '.token')
JTI=$(echo "$MINT_RESP" | jq -r '.jti')

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "error: mint failed: $MINT_RESP" >&2
  exit 1
fi
echo "==> minted bench token: jti=$JTI"

# ----------------------------------------------------------------------
# Build vegeta target file + payload
# ----------------------------------------------------------------------

PAYLOAD="$OUT_DIR/payload.json"
cat >"$PAYLOAD" <<EOF
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {"name": "read_invoice", "arguments": {"id": "bench-1"}}
}
EOF

TARGETS="$OUT_DIR/targets.txt"
cat >"$TARGETS" <<EOF
POST $GATEWAY_URL/v1/mcp
Authorization: Bearer $TOKEN
Content-Type: application/json
X-Intent-Prompt: Benchmark traffic.
@$PAYLOAD
EOF

# ----------------------------------------------------------------------
# Sweep
# ----------------------------------------------------------------------

declare -a SUMMARY_ROWS=()
# Track the highest rate that stayed under a p99 of 10ms with >= 99.9%
# success, so the report's headline can quote it as the "happy knee"
# of the curve. Picks itself based on the data, not a hard-coded rate.
HEADLINE_RATE=""
HEADLINE_P50=""
HEADLINE_P99=""
HEADLINE_SUCCESS=""

# Helper: scrape a single histogram sum/count from /metrics for the
# given check name. Returns "ms_p_avg" — derived from total_seconds /
# count, so it's a coarse mean rather than a true percentile, but
# good enough to show which check dominates.
scrape_check_avg_ms() {
  local check="$1"
  local metrics
  metrics=$(curl -sf "$GATEWAY_URL/metrics" 2>/dev/null || echo "")
  if [[ -z "$metrics" ]]; then
    echo "n/a"
    return
  fi
  # Histogram lines look like:
  #   intentgate_gateway_check_duration_seconds_sum{check="capability"} 0.123
  #   intentgate_gateway_check_duration_seconds_count{check="capability"} 42
  local sum count
  sum=$(echo "$metrics" \
    | grep -E "^intentgate_gateway_check_duration_seconds_sum\{check=\"$check\"\}" \
    | awk '{print $NF}' | head -n1)
  count=$(echo "$metrics" \
    | grep -E "^intentgate_gateway_check_duration_seconds_count\{check=\"$check\"\}" \
    | awk '{print $NF}' | head -n1)
  if [[ -z "$sum" || -z "$count" || "$count" == "0" ]]; then
    echo "n/a"
    return
  fi
  awk -v s="$sum" -v c="$count" 'BEGIN { printf "%.3f", (s/c)*1000 }'
}

for RATE in $RATES; do
  echo
  echo "==> attacking at ${RATE} req/s for $DURATION..."

  RAW="$OUT_DIR/rate-${RATE}.bin"
  REPORT="$OUT_DIR/rate-${RATE}.json"

  vegeta attack \
    -targets="$TARGETS" \
    -rate="$RATE" \
    -duration="$DURATION" \
    -timeout=10s \
    >"$RAW"

  vegeta report -type=json <"$RAW" >"$REPORT"

  ACTUAL=$(jq -r '.rate' "$REPORT")
  THROUGHPUT=$(jq -r '.throughput' "$REPORT")
  P50=$(jq -r '.latencies."50th"' "$REPORT")
  P95=$(jq -r '.latencies."95th"' "$REPORT")
  P99=$(jq -r '.latencies."99th"' "$REPORT")
  MAX=$(jq -r '.latencies.max' "$REPORT")
  SUCCESS=$(jq -r '.success' "$REPORT")
  ERRORS=$(jq -r '.errors | length' "$REPORT")

  # vegeta returns latencies in nanoseconds.
  P50_MS=$(awk -v n="$P50" 'BEGIN { printf "%.2f", n/1e6 }')
  P95_MS=$(awk -v n="$P95" 'BEGIN { printf "%.2f", n/1e6 }')
  P99_MS=$(awk -v n="$P99" 'BEGIN { printf "%.2f", n/1e6 }')
  MAX_MS=$(awk -v n="$MAX" 'BEGIN { printf "%.2f", n/1e6 }')
  SUCCESS_PCT=$(awk -v s="$SUCCESS" 'BEGIN { printf "%.2f", s*100 }')
  TPUT=$(awk -v t="$THROUGHPUT" 'BEGIN { printf "%.0f", t }')

  printf "    actual rate=%.0f throughput=%s/s p50=%sms p95=%sms p99=%sms max=%sms success=%s%%\n" \
    "$ACTUAL" "$TPUT" "$P50_MS" "$P95_MS" "$P99_MS" "$MAX_MS" "$SUCCESS_PCT"

  SUMMARY_ROWS+=("| ${RATE} | ${TPUT} | ${P50_MS} | ${P95_MS} | ${P99_MS} | ${MAX_MS} | ${SUCCESS_PCT}% | ${ERRORS} |")

  # Update the "happy knee": the highest rate so far where p99 < 10ms
  # and success >= 99.9%. Sweep is monotonically increasing, so each
  # qualifying rate strictly improves the headline.
  IS_HAPPY=$(awk -v p="$P99_MS" -v s="$SUCCESS" 'BEGIN { print (p<10 && s>=0.999) }')
  if [[ "$IS_HAPPY" == "1" ]]; then
    HEADLINE_RATE="$RATE"
    HEADLINE_P50="$P50_MS"
    HEADLINE_P99="$P99_MS"
    HEADLINE_SUCCESS="$SUCCESS_PCT"
  fi

  # Saturation guard: if success drops below 99%, the next-higher rate
  # will only show worse. Stop here.
  IS_SATURATED=$(awk -v s="$SUCCESS" 'BEGIN { print (s<0.99) }')
  if [[ "$IS_SATURATED" == "1" ]]; then
    echo "    ! saturation detected (success<99%), stopping sweep"
    break
  fi
done

# Per-check averages from the cumulative metrics scrape (across the
# whole sweep). Useful for "which check dominates?".
CHK_CAP=$(scrape_check_avg_ms "capability")
CHK_INT=$(scrape_check_avg_ms "intent")
CHK_POL=$(scrape_check_avg_ms "policy")
CHK_BUD=$(scrape_check_avg_ms "budget")
CHK_REV=$(scrape_check_avg_ms "revocation")

# ----------------------------------------------------------------------
# Write report
# ----------------------------------------------------------------------

{
  echo "# IntentGate gateway benchmarks"
  echo
  echo "Run: \`$DATESTAMP\`  "
  echo "Gateway version: \`$GATEWAY_VERSION\`  "
  echo "Profile: \`$PROFILE_NAME\`  "
  echo "Host: $HOST_DESC  "
  echo "Sweep duration per rate: \`$DURATION\`"
  echo
  if [[ -n "$HEADLINE_RATE" ]]; then
    echo "## Headline"
    echo
    echo "At **${HEADLINE_RATE} requests per second**, the gateway holds"
    echo "**p50 = ${HEADLINE_P50} ms** and **p99 = ${HEADLINE_P99} ms** with"
    echo "**${HEADLINE_SUCCESS}% success**. (Highest rate in this sweep that"
    echo "stayed under a 10 ms p99 with ≥ 99.9% success — the script"
    echo "picks this automatically from the data.)"
    echo
  fi
  echo "## End-to-end latency by request rate"
  echo
  echo "Vegeta attacks \`POST /v1/mcp\` with a one-tool-call payload at"
  echo "increasing target rates. The full pipeline runs on every"
  echo "request: token decode + HMAC verify + revocation lookup +"
  echo "policy eval + audit emit. \`success\` is the fraction of"
  echo "requests the gateway returned a 2xx for; \`errors\` counts any"
  echo "non-2xx **or** transport failure (timeouts, connection drops)."
  echo
  echo "| target rate | throughput | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | success | errors |"
  echo "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
  for row in "${SUMMARY_ROWS[@]}"; do
    echo "$row"
  done
  echo
  echo "## Average latency by check (cumulative across sweep)"
  echo
  echo "Pulled from \`/metrics\` after the sweep completes — these are"
  echo "the histogram \`sum/count\` averages by check stage. Use them"
  echo "to spot which check dominates the request budget. n/a means"
  echo "the check is disabled (its histogram has zero observations)."
  echo
  echo "| check       | mean (ms) |"
  echo "| ----------- | --------: |"
  echo "| capability  | $CHK_CAP |"
  echo "| revocation  | $CHK_REV |"
  echo "| intent      | $CHK_INT |"
  echo "| policy      | $CHK_POL |"
  echo "| budget      | $CHK_BUD |"
  echo
  echo "## Test setup"
  echo
  echo "- Gateway running in single-replica mode."
  echo "- Token minted with a 1800s TTL and 10M max-calls so neither"
  echo "  TTL nor budget caps the sweep."
  echo "- One vegeta worker on the same host as the gateway"
  echo "  (port-forwarded from the cluster). Cross-region numbers"
  echo "  will be dominated by network latency, not the gateway."
  echo "- Strict-mode flags are reported via the metrics histogram"
  echo "  presence above: a check with \`n/a\` was disabled during the"
  echo "  run. To benchmark strict mode, flip \`requireCapability /"
  echo "  Intent / Budget\` to \`true\` in the helm values, restart,"
  echo "  and re-run with \`PROFILE_NAME=strict\`."
  echo
  echo "## Reproducing"
  echo
  echo '```sh'
  echo 'export ADMIN_TOKEN=<superadmin token>'
  echo 'kubectl -n intentgate port-forward svc/ig-intentgate-gateway 8080:8080 &'
  echo 'sleep 1'
  echo './scripts/bench.sh'
  echo '```'
  echo
  echo "Knobs: \`DURATION\`, \`RATES\` (space-separated), \`PROFILE_NAME\`,"
  echo "\`GATEWAY_URL\`."
  echo
} >"$REPORT_MD"

echo
echo "==> wrote $REPORT_MD"
echo "==> raw vegeta reports in $OUT_DIR/"
