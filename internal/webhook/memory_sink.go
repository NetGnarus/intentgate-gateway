package webhook

import (
	"context"
	"sync"
)

// MemorySink stashes delivered events in an in-memory slice. Used
// by tests + by the emitter integration tests in the audit package
// when we want to assert "this audit event triggered this webhook
// event" without standing up an HTTP server.
type MemorySink struct {
	mu     sync.Mutex
	events []WebhookEvent
	// err, when non-nil, is returned from every Deliver call. Used
	// to simulate a misbehaving receiver.
	err error
}

// NewMemorySink returns an empty sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Deliver records the event (when err is unset) or returns the
// pre-set error (when err is set). Concurrent-safe.
func (m *MemorySink) Deliver(_ context.Context, ev WebhookEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, ev)
	return nil
}

// Events returns a snapshot of delivered events. Safe to call
// concurrently with Deliver.
func (m *MemorySink) Events() []WebhookEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]WebhookEvent, len(m.events))
	copy(out, m.events)
	return out
}

// SetError configures every subsequent Deliver to return the given
// error. Pass nil to clear.
func (m *MemorySink) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// Reset clears the stored events and any configured error.
func (m *MemorySink) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
	m.err = nil
}
