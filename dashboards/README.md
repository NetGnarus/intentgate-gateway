# IntentGate gateway — operational dashboards

Pre-built observability dashboards for the gateway, shipped with the repo so customers don't have to author them from scratch.

## What's here

| Path | For | What it shows |
| ---- | --- | -------------- |
| [`grafana/intentgate-gateway.json`](./grafana/intentgate-gateway.json) | Grafana 11+ | Headline RPS / p99 / deny-rate / upstream-success up top; per-check decision rate and latency in the middle; upstream + revocation + Go runtime panels below. 15 panels in 5 rows, default 5-second refresh. |

All dashboards are licensed Apache-2.0, same as the gateway itself. Edit them, fork them, ship them with your own deployment — no attribution required.

## Requirements

The gateway must be:

1. Built from `v1.6.0` or later (earlier versions emit a subset of the metrics).
2. Started with `INTENTGATE_METRICS_ENABLED=true` (off by default — exposing `/metrics` on the public port is opt-in for info-disclosure reasons).
3. Reachable from a Prometheus scraper at `GET /metrics`. The metric namespace is `intentgate_gateway_*`; the scrape config is the same as any standard Go service.

A minimal Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: intentgate-gateway
    metrics_path: /metrics
    static_configs:
      - targets: ["intentgate-gateway.your-namespace.svc:8080"]
```

## Importing the Grafana dashboard

### Manual import

1. Open Grafana → **Dashboards** → **Import**.
2. Upload `grafana/intentgate-gateway.json` (or paste the contents).
3. Select your Prometheus datasource when prompted (the dashboard references it via the `${DS_PROMETHEUS}` input variable).
4. Click **Import**. The dashboard lands at `/d/intentgate-gateway-ops`.

### kube-prometheus-stack auto-discovery

If you run `kube-prometheus-stack` (or anything else that watches for `ConfigMap` resources labeled `grafana_dashboard=1`), drop the JSON into a `ConfigMap` and apply:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: intentgate-gateway-dashboard
  labels:
    grafana_dashboard: "1"
data:
  intentgate-gateway.json: |-
    # paste the contents of grafana/intentgate-gateway.json here
```

The official IntentGate Helm chart at [`intentgate-helm`](https://github.com/NetGnarus/intentgate-helm) ships this ConfigMap by default when `dashboards.enabled=true` (set in `values.yaml`); turn it off for clusters that don't run a Grafana auto-discovery sidecar.

### Local kicking-the-tires

The fastest way to see the dashboard against live traffic is the IntentGate demo lab — clone [`intentgate-lab`](https://github.com/NetGnarus/intentgate-lab) and run `./demo.sh`. Beat 12 generates traffic and pops the dashboard open. No Kubernetes needed.

## Panel reference

The dashboard is organized top-to-bottom by *how often you'd look at it*:

**Headline (always on screen)** — RPS, p99 latency, deny rate, upstream success ratio. The four numbers a platform team glances at during an incident.

**Four-control authorization decisions** — stacked decisions per check stage (capability / intent / policy / budget / upstream) and outcome (allow / block / skip). The mental model for "which control fired when."

**Latency** — per-check p99 alongside end-to-end p50/p95/p99. When something's slow, this tells you which check is slow vs the call as a whole.

**Upstream health** — forward outcomes (success / timeout / transport / upstream_http) and latency. Distinguishes "the gateway is fine, the tool server is sick" from "the gateway itself is degraded."

**Revocation store** — lookup rate by result and p99 lookup latency. The most overlooked failure mode in a token-based system: a sick revocation backend means revocations stop landing.

**Runtime** (collapsed by default) — Go goroutines, GC pause, heap, process CPU. Open when triaging an obvious gateway-pod-side issue.

## Contributing

Found a panel that doesn't render, or a query that's wrong? Open an issue with a screenshot and the queried metric name. PRs that add new panels are welcome — keep them focused on operational signals (cardinality-safe, single-replica-safe) rather than per-tool or per-agent drill-downs (those belong in your audit log, not your metrics dashboard).
