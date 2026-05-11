package webhook

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// EmitterConfig configures the audit.Emitter adapter that bridges
// the audit fan-out into a webhook Sink.
type EmitterConfig struct {
	// Sink is the destination. Required.
	Sink Sink
	// Filter selects + projects audit events into webhook events.
	// nil falls back to [DefaultFilter] with no allowlist (all
	// high-signal events pass).
	Filter Filter
	// BufferSize is the channel capacity. Drops on overflow with
	// a WARN log. 0 → 256.
	BufferSize int
	// DeliverTimeout caps each Deliver call so a slow receiver
	// cannot pin the worker forever. 0 → 30s. Distinct from the
	// per-attempt HTTP timeout inside the HTTPSink: this is the
	// outer wall-clock budget across all retry attempts.
	DeliverTimeout time.Duration
	// Logger receives drop / failure notices.
	Logger *slog.Logger
}

// Emitter implements [audit.Emitter] by filtering + projecting audit
// events and forwarding the result to a webhook Sink on a background
// worker.
//
// The Emit contract is fire-and-forget: a slow Sink drops on
// overflow rather than blocking the request path. DroppedCount on
// [Status] surfaces the count so operators see backpressure on the
// admin endpoint.
type Emitter struct {
	cfg     EmitterConfig
	ch      chan WebhookEvent
	wg      sync.WaitGroup
	stopped atomic.Bool

	totalQueued    atomic.Uint64
	totalDelivered atomic.Uint64
	totalDropped   atomic.Uint64
	totalFailed    atomic.Uint64
	lastError      atomic.Pointer[string]
}

const (
	defaultBufferSize     = 256
	defaultDeliverTimeout = 30 * time.Second
)

// NewEmitter starts a background worker that drains the queue. Call
// [Stop] on graceful shutdown to drain pending events.
func NewEmitter(cfg EmitterConfig) *Emitter {
	if cfg.Sink == nil {
		// Defensive: returning nil here would surface as a nil-pointer
		// in main.go's wiring. A no-op emitter is safer.
		cfg.Sink = noopSink{}
	}
	if cfg.Filter == nil {
		cfg.Filter = DefaultFilter(nil)
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	}
	if cfg.DeliverTimeout <= 0 {
		cfg.DeliverTimeout = defaultDeliverTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	e := &Emitter{
		cfg: cfg,
		ch:  make(chan WebhookEvent, cfg.BufferSize),
	}
	e.wg.Add(1)
	go e.worker()
	return e
}

// Emit projects + enqueues. Non-blocking; drops with a WARN on
// overflow. Implements audit.Emitter.
func (e *Emitter) Emit(_ context.Context, ev audit.Event) {
	if e == nil || e.stopped.Load() {
		return
	}
	out, ok := e.cfg.Filter(ev)
	if !ok {
		return
	}
	e.totalQueued.Add(1)
	select {
	case e.ch <- out:
	default:
		e.totalDropped.Add(1)
		e.cfg.Logger.Warn("webhook: buffer full; dropped event",
			"event", string(out.Event),
			"tenant", out.Tenant,
		)
	}
}

// Stop closes the queue and waits for the worker to drain (bounded
// by ctx). Idempotent.
func (e *Emitter) Stop(ctx context.Context) error {
	if e == nil || e.stopped.Swap(true) {
		return nil
	}
	close(e.ch)

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Status returns the runtime counters. Mirrors siem.Status so the
// admin endpoint can compose webhook + SIEM cards in one response.
func (e *Emitter) Status() Status {
	st := Status{
		Name:        "webhook",
		Configured:  true,
		TotalSent:   e.totalDelivered.Load(),
		TotalFailed: e.totalFailed.Load() + e.totalDropped.Load(),
	}
	if msg := e.lastError.Load(); msg != nil {
		st.LastError = *msg
	}
	// Surface the configured endpoint when the sink reports it.
	if rep, ok := e.cfg.Sink.(interface{ Status() Status }); ok {
		sinkSt := rep.Status()
		st.Endpoint = sinkSt.Endpoint
	}
	return st
}

func (e *Emitter) worker() {
	defer e.wg.Done()
	for ev := range e.ch {
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.DeliverTimeout)
		err := e.cfg.Sink.Deliver(ctx, ev)
		cancel()
		if err != nil {
			e.totalFailed.Add(1)
			msg := err.Error()
			e.lastError.Store(&msg)
			e.cfg.Logger.Warn("webhook: delivery failed",
				"event", string(ev.Event),
				"err", msg,
			)
			continue
		}
		e.totalDelivered.Add(1)
		empty := ""
		e.lastError.Store(&empty)
	}
}

// noopSink is the fallback Sink used when an [Emitter] is built with
// a nil Sink. Defensive: keeps the rest of the wiring honest.
type noopSink struct{}

func (noopSink) Deliver(context.Context, WebhookEvent) error { return nil }

// Compile-time interface check.
var _ audit.Emitter = (*Emitter)(nil)
