// Package metrics holds all the Prometheus counters and histograms the
// gateway exposes on /metrics, plus the helpers handlers use to record
// against them.
//
// Design notes:
//
//  1. A custom Registry rather than the global one. The promhttp
//     handler is built from this registry, so we don't accidentally
//     leak Go runtime metrics or any third-party-registered metrics
//     to scrapers. If we want them, we add them deliberately via
//     [Metrics.RegisterGoCollector].
//
//  2. Helpers (ObserveCheck, ObserveUpstream, ObserveRevocation) hide
//     the prometheus/client_golang surface from handlers. Handlers
//     just call ig.Metrics.ObserveCheck(...) and don't import any
//     prom types. That keeps the handler-level test surface small
//     and lets us swap implementations later.
//
//  3. Cardinality discipline. Labels are limited to small bounded
//     sets (check name, decision, outcome). We deliberately do NOT
//     label by tool name, agent_id, or path beyond the route family
//     — those would explode the time-series count under real agent
//     traffic.
//
// The "intentgate_gateway_*" namespace comes through the prom
// Namespace + Subsystem opts so dashboards can filter on it cleanly.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "intentgate"
	subsystem = "gateway"
)

// Metrics owns the gateway's Prometheus instrumentation.
type Metrics struct {
	registry *prometheus.Registry

	httpRequestsTotal     *prometheus.CounterVec
	httpRequestDuration   *prometheus.HistogramVec
	checkDecisionsTotal   *prometheus.CounterVec
	checkDuration         *prometheus.HistogramVec
	upstreamForwardTotal  *prometheus.CounterVec
	upstreamForwardLat    *prometheus.HistogramVec
	revocationLookupTotal *prometheus.CounterVec
	revocationLookupLat   prometheus.Histogram
}

// New constructs the registry and all the counters/histograms.
//
// IncludeRuntimeMetrics turns on the standard Go runtime collectors
// (goroutines, GC, mem). Turn it on in production; it's cheap and
// useful for dashboards.
type Config struct {
	IncludeRuntimeMetrics bool
}

// New constructs a Metrics with all collectors registered.
func New(cfg Config) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,
		httpRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name: "http_requests_total",
			Help: "Total HTTP requests, labeled by method, route, and response status class.",
		}, []string{"method", "route", "status"}),
		httpRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name:    "http_request_duration_seconds",
			Help:    "End-to-end HTTP request duration (handler-only) by method and route.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms .. ~4s
		}, []string{"method", "route"}),
		checkDecisionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name: "check_decisions_total",
			Help: "Per-check authorization decisions (capability/intent/policy/budget/upstream × allow/block/skip).",
		}, []string{"check", "decision"}),
		checkDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name:    "check_duration_seconds",
			Help:    "Per-check evaluation duration.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 14), // 100us .. ~1.6s
		}, []string{"check"}),
		upstreamForwardTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name: "upstream_forward_total",
			Help: "Authorized tools/call forwards to the upstream MCP server, labeled by outcome.",
		}, []string{"outcome"}), // success / timeout / transport / upstream_http
		upstreamForwardLat: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name:    "upstream_forward_duration_seconds",
			Help:    "Upstream forward duration by outcome.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14), // 1ms .. ~16s
		}, []string{"outcome"}),
		revocationLookupTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name: "revocation_lookups_total",
			Help: "Revocation store lookups, labeled by result (revoked, not_revoked, error).",
		}, []string{"result"}),
		revocationLookupLat: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: subsystem,
			Name:    "revocation_lookup_duration_seconds",
			Help:    "Revocation store lookup duration.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 14),
		}),
	}

	reg.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.checkDecisionsTotal,
		m.checkDuration,
		m.upstreamForwardTotal,
		m.upstreamForwardLat,
		m.revocationLookupTotal,
		m.revocationLookupLat,
	)

	if cfg.IncludeRuntimeMetrics {
		reg.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	}

	return m
}

// Handler returns the http.Handler that serves /metrics. Built from
// the custom registry so global / third-party metrics don't leak into
// the gateway's scrape surface.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// ObserveHTTP records a finished HTTP request.
//
// route should be a stable label (the matched mux route, NOT the raw
// URL) to avoid label cardinality blowing up under request-id-style
// paths. status is the integer HTTP status; it's collapsed to a class
// label ("2xx", "4xx", ...) for cardinality discipline.
func (m *Metrics) ObserveHTTP(method, route string, status int, dur time.Duration) {
	if m == nil {
		return
	}
	m.httpRequestsTotal.WithLabelValues(method, route, statusClass(status)).Inc()
	m.httpRequestDuration.WithLabelValues(method, route).Observe(dur.Seconds())
}

// ObserveCheck records the outcome of one of the four-check stages
// (or the upstream forward step). check is one of: "capability",
// "intent", "policy", "budget", "upstream". decision is one of:
// "allow", "block", "skip".
func (m *Metrics) ObserveCheck(check, decision string, dur time.Duration) {
	if m == nil {
		return
	}
	m.checkDecisionsTotal.WithLabelValues(check, decision).Inc()
	m.checkDuration.WithLabelValues(check).Observe(dur.Seconds())
}

// ObserveUpstream records the outcome of one upstream forward attempt.
// outcome is one of: "success", "timeout", "transport", "upstream_http".
func (m *Metrics) ObserveUpstream(outcome string, dur time.Duration) {
	if m == nil {
		return
	}
	m.upstreamForwardTotal.WithLabelValues(outcome).Inc()
	m.upstreamForwardLat.WithLabelValues(outcome).Observe(dur.Seconds())
}

// ObserveRevocation records one revocation-store lookup. result is
// one of: "revoked", "not_revoked", "error".
func (m *Metrics) ObserveRevocation(result string, dur time.Duration) {
	if m == nil {
		return
	}
	m.revocationLookupTotal.WithLabelValues(result).Inc()
	m.revocationLookupLat.Observe(dur.Seconds())
}

// statusClass collapses an HTTP status code into its class label. Five
// bounded values keeps the time-series count under control regardless
// of how many distinct error codes the gateway emits.
func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	case status >= 100:
		return "1xx"
	default:
		return "unknown"
	}
}
