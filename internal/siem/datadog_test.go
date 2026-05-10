package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

func TestDatadogEmitterRequiresAPIKey(t *testing.T) {
	if _, err := NewDatadogEmitter(DatadogConfig{}); err == nil {
		t.Fatal("expected error without APIKey")
	}
}

func TestDatadogEmitterFlushesBatch(t *testing.T) {
	var captured atomic.Value
	captured.Store([]ddLog{})
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if got := r.Header.Get("DD-API-KEY"); got != "ddkey" {
			t.Errorf("auth header = %q, want 'ddkey'", got)
		}
		body, _ := io.ReadAll(r.Body)
		var got []ddLog
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decode: %v (body=%s)", err, string(body))
		}
		captured.Store(append(captured.Load().([]ddLog), got...))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	em, err := NewDatadogEmitter(DatadogConfig{
		APIKey:  "ddkey",
		Site:    "datadoghq.com",
		Service: "intentgate-test",
		Tags:    []string{"env:dev", "team:sec"},
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Override URL to point at the test server (Site-derived URL would
	// hit real Datadog).
	em.url = srv.URL
	em.be.Stop(context.Background())
	em.be = newBatchEmitter(batchConfig{
		Name:   "datadog",
		Flush:  httpFlusher(em.cfg.HTTPClient, em.buildRequest),
		Logger: quietLogger(),
	})

	allowEvent := audit.NewEvent(audit.DecisionAllow, "read_invoice")
	allowEvent.AgentID = "agent-a"
	em.Emit(context.Background(), allowEvent)

	blockEvent := audit.NewEvent(audit.DecisionBlock, "send_email")
	blockEvent.AgentID = "agent-b"
	blockEvent.Reason = "tool not in whitelist"
	em.Emit(context.Background(), blockEvent)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if hits.Load() == 0 {
		t.Fatal("expected at least one POST")
	}
	got := captured.Load().([]ddLog)
	if len(got) != 2 {
		t.Fatalf("want 2 ddLog records, got %d", len(got))
	}
	if got[0].Service != "intentgate-test" {
		t.Errorf("service = %q, want intentgate-test", got[0].Service)
	}
	if got[0].Tags != "env:dev,team:sec" {
		t.Errorf("tags = %q", got[0].Tags)
	}
	if got[1].Status != "warn" {
		t.Errorf("block event status = %q, want warn", got[1].Status)
	}
	if got[0].Status != "info" {
		t.Errorf("allow event status = %q, want info", got[0].Status)
	}
	if got[1].Audit.Reason != "tool not in whitelist" {
		t.Errorf("audit payload not nested: %+v", got[1].Audit)
	}

	st := em.Status()
	if !st.Configured {
		t.Error("status.Configured = false, want true")
	}
	if st.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", st.TotalEvents)
	}
	if st.LastFlushTs.IsZero() {
		t.Error("LastFlushTs not populated after successful flush")
	}
}

func TestDatadogEmitterTransientErrorRetained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	em, err := NewDatadogEmitter(DatadogConfig{
		APIKey: "ddkey",
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	em.url = srv.URL
	em.be.Stop(context.Background())
	em.be = newBatchEmitter(batchConfig{
		Name:   "datadog",
		Flush:  httpFlusher(em.cfg.HTTPClient, em.buildRequest),
		Logger: quietLogger(),
	})
	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = em.Stop(ctx)

	st := em.Status()
	if st.LastError == "" {
		t.Error("expected LastError to be populated on 500")
	}
}
