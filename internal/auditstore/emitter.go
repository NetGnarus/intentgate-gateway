package auditstore

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// EmitterConfig configures an async emitter that fans events out to a
// [Store].
type EmitterConfig struct {
	// Store is the backing store. Required.
	Store Store
	// BufferSize is the channel capacity that holds events between
	// Emit and the worker's Insert. When the buffer is full, Emit
	// drops the event (and increments DroppedCount). The drop is
	// logged at warn-level once per drop epoch so the operator
	// notices but logs don't drown.
	//
	// The default (1024) is a few seconds of typical agent traffic;
	// busy deployments should turn it up.
	BufferSize int
	// InsertTimeout is the per-insert deadline. The audit.Emitter
	// contract is "buffer and drop" — we don't want a hung Postgres
	// to back up the gateway, so we cap each insert and continue.
	// Default 2s.
	InsertTimeout time.Duration
	// Logger receives drop / error notices. nil falls back to the
	// default logger.
	Logger *slog.Logger
}

// Emitter writes events to a Store asynchronously, satisfying the
// audit.Emitter contract (Emit MUST NOT block).
//
// One worker goroutine drains the buffer; Stop() closes the buffer
// and waits for the worker to drain in-flight events. Use Stop() in
// a graceful-shutdown path to avoid losing events that were emitted
// just before SIGTERM.
type Emitter struct {
	cfg     EmitterConfig
	ch      chan audit.Event
	closed  atomic.Bool
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// NewEmitter returns an emitter and starts its worker goroutine.
func NewEmitter(cfg EmitterConfig) *Emitter {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	if cfg.InsertTimeout <= 0 {
		cfg.InsertTimeout = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	e := &Emitter{
		cfg: cfg,
		ch:  make(chan audit.Event, cfg.BufferSize),
	}
	e.wg.Add(1)
	go e.run()
	return e
}

// Emit hands the event to the worker. Non-blocking: drops on full
// buffer or after Stop().
func (e *Emitter) Emit(_ context.Context, ev audit.Event) {
	if e == nil || e.closed.Load() {
		return
	}
	select {
	case e.ch <- ev:
	default:
		// Buffer full; drop. We log once per 1k drops so a sustained
		// overload is visible without flooding logs.
		n := e.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			e.cfg.Logger.Warn("auditstore: event buffer full, dropping",
				"dropped_total", n,
				"buffer_size", e.cfg.BufferSize)
		}
	}
}

// Dropped returns the running drop counter (cumulative since process
// start). Useful for tests and for an operator-facing metric.
func (e *Emitter) Dropped() uint64 {
	return e.dropped.Load()
}

// Stop closes the channel and waits for the worker to drain. Safe to
// call multiple times. After Stop, Emit silently drops.
func (e *Emitter) Stop(ctx context.Context) error {
	if !e.closed.CompareAndSwap(false, true) {
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

func (e *Emitter) run() {
	defer e.wg.Done()
	for ev := range e.ch {
		ctx, cancel := context.WithTimeout(context.Background(), e.cfg.InsertTimeout)
		if err := e.cfg.Store.Insert(ctx, ev); err != nil {
			e.cfg.Logger.Warn("auditstore: insert failed",
				"err", err,
				"tool", ev.Tool,
				"decision", ev.Decision)
		}
		cancel()
	}
}
