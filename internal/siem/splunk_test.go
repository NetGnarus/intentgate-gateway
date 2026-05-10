package siem

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSplunkEmitterRequiresURLAndToken(t *testing.T) {
	if _, err := NewSplunkEmitter(SplunkConfig{Token: "x"}); err == nil {
		t.Fatal("expected error without URL")
	}
	if _, err := NewSplunkEmitter(SplunkConfig{URL: "http://x"}); err == nil {
		t.Fatal("expected error without Token")
	}
}

func TestSplunkEmitterFlushesEvents(t *testing.T) {
	var bodies atomic.Value
	bodies.Store([][]byte{})
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if got := r.Header.Get("Authorization"); got != "Splunk testtoken" {
			t.Errorf("auth header = %q, want 'Splunk testtoken'", got)
		}
		body, _ := io.ReadAll(r.Body)
		curr := bodies.Load().([][]byte)
		bodies.Store(append(curr, body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em, err := NewSplunkEmitter(SplunkConfig{
		URL:    srv.URL,
		Token:  "testtoken",
		Index:  "intentgate",
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	for i := 0; i < 3; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if hits.Load() == 0 {
		t.Fatal("expected at least one POST")
	}

	all := bodies.Load().([][]byte)
	combined := make([]byte, 0)
	for _, b := range all {
		combined = append(combined, b...)
	}

	// HEC batch is newline-delimited JSON envelopes.
	lines := strings.Split(strings.TrimSpace(string(combined)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 envelope lines, got %d (body=%q)", len(lines), string(combined))
	}
	var env hecEvent
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Index != "intentgate" {
		t.Errorf("index missing on envelope: %+v", env)
	}
	if env.Source != "intentgate" || env.Sourcetype != "_json" {
		t.Errorf("default source/sourcetype lost: %+v", env)
	}
	if env.Event.Tool != "x" {
		t.Errorf("event payload missing: %+v", env.Event)
	}

	st := em.Status()
	if !st.Configured || st.Endpoint != srv.URL {
		t.Errorf("status: %+v", st)
	}
	if st.TotalEvents != 3 {
		t.Errorf("flushed = %d, want 3", st.TotalEvents)
	}
}

func TestSplunkEmitterPermanentErrorRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	em, err := NewSplunkEmitter(SplunkConfig{
		URL:    srv.URL,
		Token:  "bad",
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = em.Stop(ctx)

	st := em.Status()
	if st.LastError == "" {
		t.Error("expected LastError to be populated on 401")
	}
	if st.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d, want 0 on auth failure", st.TotalEvents)
	}
}

func TestSplunkEmitterDropsOnFullBuffer(t *testing.T) {
	// Slow server + tiny buffer guarantees overflow.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(block)

	em, err := NewSplunkEmitter(SplunkConfig{
		URL:    srv.URL,
		Token:  "x",
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Override the batch emitter buffer to something tiny by re-creating.
	em.be.Stop(context.Background())
	em.be = newBatchEmitter(batchConfig{
		Name:       "splunk",
		Flush:      em.be.cfg.Flush,
		BufferSize: 2,
		BatchSize:  1,
		Logger:     quietLogger(),
	})

	for i := 0; i < 100; i++ {
		em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	}
	// Allow the worker's first inflight Flush to consume one slot.
	time.Sleep(50 * time.Millisecond)

	if em.Status().DroppedCount == 0 {
		t.Error("expected drops under tiny-buffer + slow-server")
	}

	// Cleanly drain so the worker goroutine doesn't leak into the next
	// test. close(block) above unblocks the handler so any inflight
	// Flush returns; ctx caps the wait.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = em.Stop(ctx)
}
