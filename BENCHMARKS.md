# IntentGate gateway benchmarks

Run: `2026-05-11 17:36 UTC`
Gateway version: `dev`
Profile: `in-cluster`
Host: in-cluster Job, 10 CPUs
Sweep duration per rate: `30s`

## Headline

At **500 requests per second**, the gateway holds
**p50 = 0.88 ms** and **p99 = 9.50 ms** with
**100.00% success**. (Highest rate in this sweep that
stayed under a 10 ms p99 with >= 99.9% success — the script picks
this automatically.)

## End-to-end latency by request rate

Vegeta attacks `POST /v1/mcp` IN-CLUSTER against the gateway Service
(cluster DNS, no port-forward). The full pipeline runs on every
request: token decode + HMAC verify + revocation lookup + policy
eval + audit emit.

| target rate | throughput | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | success | errors |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 100 | 2.24 | 4.92 | 9.07 | 90.52 | 100.00% | 0 |
| 500 | 500 | 0.88 | 1.32 | 9.50 | 63.50 | 100.00% | 0 |
| 1000 | 1000 | 0.84 | 1.50 | 19.46 | 239.66 | 100.00% | 0 |
| 2000 | 856 | 874.24 | 8191.35 | 9685.52 | 10005.71 | 57.01% | 1003 |

## Average latency by check (cumulative across sweep)

| check       | mean (ms) |
| ----------- | --------: |
| capability  | n/a |
| revocation  | n/a |
| intent      | n/a |
| policy      | n/a |
| budget      | n/a |

## Test setup

- Gateway running in the same cluster; vegeta running as a Job in
  the same namespace. No port-forward in the path.
- Token minted with 1800s TTL and 10M max-calls so neither TTL
  nor budget caps the sweep.

## Reproducing

```sh
kubectl -n intentgate delete job intentgate-bench --ignore-not-found
kubectl apply -n intentgate -f scripts/bench-job.yaml
kubectl -n intentgate logs -f job/intentgate-bench > BENCHMARKS.md
```

Knobs via env on the Job spec: `DURATION`, `RATES`, `PROFILE_NAME`,
`GATEWAY_URL`.
