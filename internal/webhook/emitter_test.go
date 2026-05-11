package webhook

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// emitterAndSink returns a wired (emitter, sink) pair for tests.
func emitterAndSink(t *testing.T) (*Emitter, *MemorySink) {
	t.Helper()
	sink := NewMemorySink()
	em := NewEmitter(EmitterConfig{
		Sink:           sink,
		Filter:         DefaultFilter(nil),
		BufferSize:     16,
		DeliverTimeout: time.Second,
	})
	return em, sink
}

// waitForDelivered polls Status until totalDelivered >= n or
// the deadline fires. Avoids racing against the worker goroutine.
func waitForDelivered(t *testing.T, em *Emitter, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if em.Status().TotalSent >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("delivered=%d want %d after 2s", em.Status().TotalSent, n)
}

// --- happy path --------------------------------------------

func TestEmitterDeliversFilteredEvent(t *testing.T) {
	em, sink := emitterAndSink(t)
	defer em.Stop(context.Background())

	em.Emit(context.Background(), audit.NewEvent(audit.DecisionBlock, "transfer_funds"))
	waitForDelivered(t, em, 1)

	evts := sink.Events()
	if len(evts) != 1 {
		t.Fatalf("delivered=%d want 1", len(evts))
	}
	if evts[0].Event != EventDeny {
		t.Errorf("event=%q want deny", evts[0].Event)
	}
}

// Routine allows don't even reach the worker.
func TestEmitterSkipsRoutineAllow(t *testing.T) {
	em, sink := emitterAndSink(t)
	defer em.Stop(context.Background())

	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "read_invoice"))
	// Give the worker a beat to misbehave if it's going to.
	time.Sleep(20 * time.Millisecond)
	if got := len(sink.Events()); got != 0 {
		t.Errorf("delivered=%d want 0 (routine allow filtered)", got)
	}
}

// --- buffer drop on overflow --------------------------------

func TestEmitterDropsOnOverflow(t *testing.T) {
	// Block the sink so events pile up.
	slowSink := NewMemorySink()
	blocked := make(chan struct{})
	slowSink.SetError(errors.New("blocked"))
	// Build emitter with tiny buffer.
	em := NewEmitter(EmitterConfig{
		Sink:           slowSinkWithGate{MemorySink: slowSink, gate: blocked},
		Filter:         DefaultFilter(nil),
		BufferSize:     2,
		DeliverTimeout: time.Second,
	})
	defer em.Stop(context.Background())

	// Fire more than fits.
	for i := 0; i < 10; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionBlock, "x"))
	}
	// Release the gate so the worker drains its in-flight item.
	close(blocked)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		st := em.Status()
		// We expect SOME drops (buffer=2, fired 10) and SOME failures
		// recorded (the sink errors). The exact split depends on
		// scheduling but both should be nonzero.
		if st.TotalFailed >= 2 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Errorf("expected drops + failures; got %+v", em.Status())
}

// slowSinkWithGate blocks the FIRST Deliver call until the gate closes,
// then delegates to the wrapped MemorySink (which is configured to
// always error). Used to provoke overflow without standing up an
// HTTP server.
type slowSinkWithGate struct {
	*MemorySink
	gate chan struct{}
	done bool
}

func (s slowSinkWithGate) Deliver(ctx context.Context, ev WebhookEvent) error {
	if !s.done {
		<-s.gate
	}
	return s.MemorySink.Deliver(ctx, ev)
}

// --- stop drains pending --------------------------------------

func TestEmitterStopDrainsPending(t *testing.T) {
	em, sink := emitterAndSink(t)

	for i := 0; i < 5; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionBlock, "x"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := len(sink.Events()); got != 5 {
		t.Errorf("delivered=%d want 5 after Stop drain", got)
	}
}

// --- stop is idempotent --------------------------------------

func TestEmitterStopIdempotent(t *testing.T) {
	em, _ := emitterAndSink(t)
	ctx := context.Background()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	// Second stop is a no-op.
	if err := em.Stop(ctx); err != nil {
		t.Errorf("second stop should be no-op, got %v", err)
	}
	// Emit after stop is a no-op (no panic, no enqueue).
	em.Emit(ctx, audit.NewEvent(audit.DecisionBlock, "x"))
}

// --- audit.Emitter interface conformance ----------------------

func TestEmitterImplementsAuditEmitter(t *testing.T) {
	em, _ := emitterAndSink(t)
	defer em.Stop(context.Background())
	var _ audit.Emitter = em
}
