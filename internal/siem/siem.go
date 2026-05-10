// Package siem ships the gateway's audit events to third-party
// security-information-and-event-management systems.
//
// Each supported destination (Splunk HEC, Datadog Logs Intake) is an
// implementation of [audit.Emitter] that batches events, flushes them
// over HTTP, and reports a small status struct the admin UI surfaces.
//
// # Why in the gateway
//
// Audit emission is already a fan-out (stdout + auditstore Postgres
// from session 22). Adding two more sinks via the same FanOutEmitter
// keeps the control flow obvious and avoids running a separate
// forwarder daemon — one binary, one helm chart, one pod.
//
// # Failure isolation
//
// Each emitter has its own buffer + worker. A slow or misconfigured
// destination drops on overflow, never blocks the request path, and
// never affects the other emitters in the fan-out. This matches the
// auditstore.Emitter contract and the broader audit.Emitter rule
// (Emit MUST NOT block).
//
// # What we send
//
// The audit.Event struct is OCSF-lite. Splunk HEC accepts the event
// body verbatim under the "event" key; Datadog Logs Intake takes a
// JSON array. Both are happy with the underscore_case keys; no field
// renaming step needed.
package siem

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// Stoppable is implemented by every emitter in this package. main.go
// holds the concrete types so it can call Stop on graceful shutdown.
type Stoppable interface {
	Stop(ctx context.Context) error
}

// Status is the read-only snapshot the admin endpoint returns. Field
// names match the JSON wire shape the console renders. Sensitive
// configuration (tokens, API keys) is NEVER included — only labels
// and counters.
type Status struct {
	// Name is a stable identifier ("splunk", "datadog").
	Name string `json:"name"`
	// Configured is true when the operator has supplied enough env
	// vars to wire the destination. False means "this card is shown
	// but greyed out".
	Configured bool `json:"configured"`
	// Endpoint is the POST URL the emitter targets. Useful for
	// "double-check that's the right Splunk", and innocuous to
	// expose.
	Endpoint string `json:"endpoint,omitempty"`
	// LastFlushTs is the timestamp of the last *successful* flush, or
	// the zero Time when none has happened yet.
	LastFlushTs time.Time `json:"last_flush_ts,omitempty"`
	// TotalEvents is the cumulative number of events the worker has
	// flushed successfully since process start.
	TotalEvents uint64 `json:"total_events"`
	// DroppedCount is the cumulative number of events dropped because
	// the buffer was full when Emit fired. Sustained drops indicate
	// the destination is too slow or that BufferSize is too small.
	DroppedCount uint64 `json:"dropped_count"`
	// LastError is the most recent error message from the worker, or
	// the empty string when the destination is healthy.
	LastError string `json:"last_error,omitempty"`
}

// StatusReporter is the (small) interface the admin endpoint uses to
// collect statuses across configured emitters.
type StatusReporter interface {
	Status() Status
}

// counters is a shared bag of atomics used by every emitter to track
// flushed/dropped counts. Lifted into its own type so the test suite
// can assert on them without poking emitter internals.
type counters struct {
	flushed atomic.Uint64
	dropped atomic.Uint64
	// lastFlushNs holds the most recent successful flush timestamp as
	// nanoseconds since unix epoch. atomic.Int64 keeps Status() lock-
	// free.
	lastFlushNs atomic.Int64
	// lastError holds the most recent worker error message. atomic
	// pointer so we can swap a *string without locking.
	lastError atomic.Pointer[string]
}

func (c *counters) recordFlush(n int) {
	c.flushed.Add(uint64(n))
	c.lastFlushNs.Store(time.Now().UnixNano())
	empty := ""
	c.lastError.Store(&empty)
}

func (c *counters) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	c.lastError.Store(&msg)
}

func (c *counters) recordDrop(n int) {
	c.dropped.Add(uint64(n))
}

// snapshot reads the counters into a [Status] frame.
func (c *counters) snapshot(name, endpoint string, configured bool) Status {
	st := Status{
		Name:         name,
		Endpoint:     endpoint,
		Configured:   configured,
		TotalEvents:  c.flushed.Load(),
		DroppedCount: c.dropped.Load(),
	}
	if ns := c.lastFlushNs.Load(); ns > 0 {
		st.LastFlushTs = time.Unix(0, ns).UTC()
	}
	if msg := c.lastError.Load(); msg != nil {
		st.LastError = *msg
	}
	return st
}

// Compile-time interface checks (light, but they catch refactor regressions).
var (
	_ audit.Emitter  = (*SplunkEmitter)(nil)
	_ audit.Emitter  = (*DatadogEmitter)(nil)
	_ audit.Emitter  = (*SentinelEmitter)(nil)
	_ Stoppable      = (*SplunkEmitter)(nil)
	_ Stoppable      = (*DatadogEmitter)(nil)
	_ Stoppable      = (*SentinelEmitter)(nil)
	_ StatusReporter = (*SplunkEmitter)(nil)
	_ StatusReporter = (*DatadogEmitter)(nil)
	_ StatusReporter = (*SentinelEmitter)(nil)
)
