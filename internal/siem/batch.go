package siem

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// flusher is the per-destination "send these events" callback.
// Implementations must serialise + POST + return error on retryable
// failure. Non-retryable errors (auth, malformed body) should still
// be returned — the worker logs and clears the batch rather than
// holding it forever.
type flusher func(ctx context.Context, events []audit.Event) error

// batchConfig configures a [batchEmitter].
type batchConfig struct {
	// Name is a short identifier used in logs and Status.
	Name string
	// Flush is the destination-specific POST callback.
	Flush flusher
	// BufferSize is the channel capacity. Drops on overflow.
	BufferSize int
	// BatchSize triggers a flush as soon as this many events
	// accumulate in the worker's pending slice.
	BatchSize int
	// FlushInterval triggers a periodic flush regardless of batch
	// fullness, so a low-traffic gateway still ships events promptly.
	FlushInterval time.Duration
	// FlushTimeout caps each Flush call so a slow destination cannot
	// pin the worker forever.
	FlushTimeout time.Duration
	// Logger receives drop / error / startup notices.
	Logger *slog.Logger
}

const (
	defaultBufferSize    = 4096
	defaultBatchSize     = 100
	defaultFlushInterval = 5 * time.Second
	defaultFlushTimeout  = 10 * time.Second
)

func (c *batchConfig) applyDefaults() {
	if c.BufferSize <= 0 {
		c.BufferSize = defaultBufferSize
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultBatchSize
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = defaultFlushInterval
	}
	if c.FlushTimeout <= 0 {
		c.FlushTimeout = defaultFlushTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// batchEmitter is the shared worker every SIEM emitter delegates to.
// Concrete emitters (SplunkEmitter, DatadogEmitter) wrap one of these
// and surface destination-specific config.
type batchEmitter struct {
	cfg      batchConfig
	ch       chan audit.Event
	closed   atomic.Bool
	wg       sync.WaitGroup
	counters counters
}

func newBatchEmitter(cfg batchConfig) *batchEmitter {
	cfg.applyDefaults()
	be := &batchEmitter{
		cfg: cfg,
		ch:  make(chan audit.Event, cfg.BufferSize),
	}
	be.wg.Add(1)
	go be.run()
	return be
}

// Emit hands the event to the worker. Non-blocking; drops on full
// buffer or after Stop.
func (b *batchEmitter) Emit(_ context.Context, ev audit.Event) {
	if b == nil || b.closed.Load() {
		return
	}
	select {
	case b.ch <- ev:
	default:
		n := b.counters.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			b.cfg.Logger.Warn("siem: event buffer full, dropping",
				"emitter", b.cfg.Name,
				"dropped_total", n,
				"buffer_size", b.cfg.BufferSize)
		}
	}
}

// Stop closes the channel and waits for the worker to drain. Safe to
// call multiple times. Honors ctx.Done() so SIGTERM with a tight
// deadline still returns instead of hanging on a slow destination.
func (b *batchEmitter) Stop(ctx context.Context) error {
	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(b.ch)
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *batchEmitter) run() {
	defer b.wg.Done()

	pending := make([]audit.Event, 0, b.cfg.BatchSize)
	tick := time.NewTicker(b.cfg.FlushInterval)
	defer tick.Stop()

	flush := func() {
		if len(pending) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), b.cfg.FlushTimeout)
		err := b.cfg.Flush(ctx, pending)
		cancel()
		if err != nil {
			b.cfg.Logger.Warn("siem: flush failed",
				"emitter", b.cfg.Name,
				"events", len(pending),
				"err", err)
			b.counters.recordError(err)
			// Drop the batch on flush error. We could buffer + retry,
			// but the [audit.Emitter] contract is best-effort and the
			// auditstore.PostgresStore is the durable record of every
			// decision. SIEM is a duplicate stream, not the source of
			// truth.
		} else {
			b.counters.recordFlush(len(pending))
		}
		pending = pending[:0]
	}

	for {
		select {
		case ev, ok := <-b.ch:
			if !ok {
				flush()
				return
			}
			pending = append(pending, ev)
			if len(pending) >= b.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// httpFlusher is a small helper that turns an HTTP request builder
// into a flusher-compatible function. Concrete emitters use it so
// the batch loop doesn't grow per-destination special cases.
func httpFlusher(client *http.Client, build func(events []audit.Event) (*http.Request, error)) flusher {
	return func(ctx context.Context, events []audit.Event) error {
		req, err := build(events)
		if err != nil {
			return err
		}
		req = req.WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return &transientHTTPError{status: resp.StatusCode}
		}
		if resp.StatusCode >= 400 {
			return &permanentHTTPError{status: resp.StatusCode}
		}
		return nil
	}
}

type transientHTTPError struct{ status int }

func (e *transientHTTPError) Error() string {
	return http.StatusText(e.status) + " (transient)"
}

type permanentHTTPError struct{ status int }

func (e *permanentHTTPError) Error() string {
	return http.StatusText(e.status) + " (permanent — check token / config)"
}
