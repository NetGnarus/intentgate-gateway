# IntentGate gateway benchmarks

Run: `2026-05-10 19:54 UTC`  
Gateway version: `dev` (locally-built, untagged)  
Profile: `as-deployed` (single-replica, in-memory budget store, no upstream tool server, capability/intent/budget non-strict)  
Host: Darwin/arm64, 10 cores  
Sweep duration per rate: `30s`

## Headline

At **2,000 requests per second**, the gateway holds **p50 = 0.77 ms** and **p99 = 1.50 ms** with **100% success**. Throughput climbs linearly from 100 → 2,000 RPS with a falling p99 (connections reuse instead of warming up). The first sign of saturation appears between 2k and 4k RPS: at 4,000 the gateway sustains ~3,992 RPS but p50 jumps 50× to 37 ms — clearly a ceiling, but worth measuring with a co-located vegeta before blaming the gateway, since `kubectl port-forward` is also in the path and is not built for throughput.

## End-to-end latency by request rate

Vegeta attacks `POST /v1/mcp` with a one-tool-call payload at
increasing target rates. The full pipeline runs on every
request: token decode + HMAC verify + revocation lookup +
policy eval + audit emit. `success` is the fraction of
requests the gateway returned a 2xx for; `errors` counts any
non-2xx **or** transport failure (timeouts, connection drops).

| target rate | throughput | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | success | errors |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 100 | 3.47 | 5.96 | 8.79 | 27.65 | 100.00% | 0 |
| 500 | 500 | 1.57 | 2.85 | 4.84 | 14.61 | 100.00% | 0 |
| 1000 | 1000 | 0.97 | 1.50 | 2.67 | 33.56 | 100.00% | 0 |
| 2000 | 2000 | 0.77 | 0.93 | 1.50 | 33.04 | 100.00% | 0 |
| 4000 | 3992 | 37.09 | 216.34 | 364.81 | 672.04 | 100.00% | 0 |

## Average latency by check (cumulative across sweep)

Pulled from `/metrics` after the sweep completes — these are
the histogram `sum/count` averages by check stage. Use them
to spot which check dominates the request budget. n/a means
the check is disabled (its histogram has zero observations).

| check       | mean (ms) |
| ----------- | --------: |
| capability  | 0.040 |
| revocation  | n/a |
| intent      | 4.086 |
| policy      | 0.107 |
| budget      | 0.003 |

## Test setup

- Gateway running in single-replica mode.
- Token minted with a 1800s TTL and 10M max-calls so neither
  TTL nor budget caps the sweep.
- One vegeta worker on the same host as the gateway
  (port-forwarded from the cluster). Cross-region numbers
  will be dominated by network latency, not the gateway.
- Strict-mode flags are reported via the metrics histogram
  presence above: a check with `n/a` was disabled during the
  run. To benchmark strict mode, flip `requireCapability /
  Intent / Budget` to `true` in the helm values, restart,
  and re-run with `PROFILE_NAME=strict`.

## Reproducing

```sh
export ADMIN_TOKEN=<superadmin token>
kubectl -n intentgate port-forward svc/ig-intentgate-gateway 8080:8080 &
sleep 1
./scripts/bench.sh
```

Knobs: `DURATION`, `RATES` (space-separated), `PROFILE_NAME`,
`GATEWAY_URL`.

