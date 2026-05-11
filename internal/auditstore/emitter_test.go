package auditstore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// fakeStore counts inserts and optionally injects an error/delay.
type fakeStore struct {
	inserted atomic.Uint64
	delay    time.Duration
	err      error
}

func (s *fakeStore) Insert(ctx context.Context, _ audit.Event) error {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.err != nil {
		return s.err
	}
	s.inserted.Add(1)
	return nil
}
func (s *fakeStore) Query(context.Context, QueryFilter) ([]audit.Event, error) {
	return nil, nil
}
func (s *fakeStore) Count(context.Context, QueryFilter) (int64, error) { return 0, nil }
func (s *fakeStore) VerifyChain(context.Context, VerifyFilter) (VerifyResult, error) {
	return VerifyResult{OK: true}, nil
}
func (s *fakeStore) Close() error { return nil }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEmitterDeliversEvents(t *testing.T) {
	store := &fakeStore{}
	em := NewEmitter(EmitterConfig{Store: store, Logger: quietLogger()})

	for i := 0; i < 50; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if got := store.inserted.Load(); got != 50 {
		t.Errorf("want 50 inserts, got %d", got)
	}
	if d := em.Dropped(); d != 0 {
		t.Errorf("want 0 drops, got %d", d)
	}
}

func TestEmitterDropsOnFullBuffer(t *testing.T) {
	// Slow store + tiny buffer guarantees the buffer fills before the
	// worker drains it.
	store := &fakeStore{delay: 50 * time.Millisecond}
	em := NewEmitter(EmitterConfig{
		Store:      store,
		BufferSize: 2,
		Logger:     quietLogger(),
	})

	for i := 0; i < 100; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	}

	if em.Dropped() == 0 {
		t.Error("expected drops under tiny-buffer + slow-store")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = em.Stop(ctx)
}

func TestEmitterEmitAfterStopIsNoOp(t *testing.T) {
	store := &fakeStore{}
	em := NewEmitter(EmitterConfig{Store: store, Logger: quietLogger()})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	// No panic, no insert.
	if got := store.inserted.Load(); got != 0 {
		t.Errorf("want 0 inserts post-stop, got %d", got)
	}
}

func TestEmitterStoreErrorDoesNotKillWorker(t *testing.T) {
	// Worker should keep draining after an error.
	store := &fakeStore{err: errors.New("simulated")}
	em := NewEmitter(EmitterConfig{Store: store, Logger: quietLogger()})

	for i := 0; i < 10; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// Stop returns once the worker exits; no events succeeded but the
	// worker shouldn't have crashed.
	if got := store.inserted.Load(); got != 0 {
		t.Errorf("simulated error should yield 0 inserts, got %d", got)
	}
}
