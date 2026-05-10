package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/audit"
)

// dual returns a (auth-server, ingest-server) pair. Auth issues a
// fixed token; ingest captures bodies + tracks bearer headers.
type dual struct {
	auth   *httptest.Server
	ingest *httptest.Server

	authHits   atomic.Int32
	ingestHits atomic.Int32

	tokenIssued string
	bodies      atomic.Value // [][]byte
	bearers     atomic.Value // []string
}

func newDual(t *testing.T, ingestStatus int) *dual {
	t.Helper()
	d := &dual{tokenIssued: "fake-bearer-token"}
	d.bodies.Store([][]byte{})
	d.bearers.Store([]string{})

	d.auth = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.authHits.Add(1)
		// Sanity: require POST + correct grant_type + correct scope.
		if r.Method != http.MethodPost {
			t.Errorf("auth: method = %q, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "grant_type=client_credentials") {
			t.Errorf("auth: missing client_credentials grant: %q", bodyStr)
		}
		if !strings.Contains(bodyStr, "scope=https") || !strings.Contains(bodyStr, "monitor.azure.com") {
			t.Errorf("auth: scope missing or wrong: %q", bodyStr)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + d.tokenIssued + `","expires_in":3599,"token_type":"Bearer"}`))
	}))

	d.ingest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.ingestHits.Add(1)
		bearer := r.Header.Get("Authorization")
		curr := d.bearers.Load().([]string)
		d.bearers.Store(append(curr, bearer))
		body, _ := io.ReadAll(r.Body)
		bodies := d.bodies.Load().([][]byte)
		d.bodies.Store(append(bodies, body))
		w.WriteHeader(ingestStatus)
	}))

	return d
}

func (d *dual) close() {
	d.auth.Close()
	d.ingest.Close()
}

func newSentinelTestEmitter(t *testing.T, d *dual) *SentinelEmitter {
	t.Helper()
	em, err := NewSentinelEmitter(SentinelConfig{
		DCEUrl:         d.ingest.URL,
		DCRImmutableID: "dcr-test",
		StreamName:     "Custom-IntentGate_CL",
		TenantID:       "tenant-id",
		ClientID:       "client-id",
		ClientSecret:   "client-secret",
		AuthEndpoint:   d.auth.URL,
		Logger:         quietLogger(),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return em
}

func TestSentinelEmitterValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*SentinelConfig)
	}{
		{"missing DCEUrl", func(c *SentinelConfig) { c.DCEUrl = "" }},
		{"missing DCRImmutableID", func(c *SentinelConfig) { c.DCRImmutableID = "" }},
		{"missing StreamName", func(c *SentinelConfig) { c.StreamName = "" }},
		{"missing TenantID", func(c *SentinelConfig) { c.TenantID = "" }},
		{"missing ClientID", func(c *SentinelConfig) { c.ClientID = "" }},
		{"missing ClientSecret", func(c *SentinelConfig) { c.ClientSecret = "" }},
	}
	base := SentinelConfig{
		DCEUrl: "http://dce.example", DCRImmutableID: "dcr",
		StreamName: "Custom-X_CL", TenantID: "t", ClientID: "c", ClientSecret: "s",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			if _, err := NewSentinelEmitter(cfg); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestSentinelEmitterFlushesBatch(t *testing.T) {
	d := newDual(t, http.StatusNoContent)
	defer d.close()
	em := newSentinelTestEmitter(t, d)

	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "read_invoice"))
	em.Emit(context.Background(), audit.NewEvent(audit.DecisionBlock, "delete_record"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if d.authHits.Load() != 1 {
		t.Errorf("auth hits = %d, want 1 (token cached)", d.authHits.Load())
	}
	if d.ingestHits.Load() == 0 {
		t.Fatal("expected ingest POST")
	}
	bearers := d.bearers.Load().([]string)
	if len(bearers) == 0 || bearers[0] != "Bearer fake-bearer-token" {
		t.Errorf("ingest bearer = %v, want Bearer fake-bearer-token", bearers)
	}

	// Body is a JSON array of audit events.
	bodies := d.bodies.Load().([][]byte)
	if len(bodies) == 0 {
		t.Fatal("no captured ingest bodies")
	}
	var got []audit.Event
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, string(bodies[0]))
	}
	if len(got) != 2 {
		t.Errorf("want 2 events, got %d", len(got))
	}

	st := em.Status()
	if !st.Configured || st.Endpoint != d.ingest.URL {
		t.Errorf("status: %+v", st)
	}
	if st.TotalEvents != 2 {
		t.Errorf("flushed = %d, want 2", st.TotalEvents)
	}
}

func TestSentinelEmitterCachesToken(t *testing.T) {
	d := newDual(t, http.StatusNoContent)
	defer d.close()
	em := newSentinelTestEmitter(t, d)

	// Force two distinct flushes by giving the worker a tiny flush
	// interval. With the default 5s interval, only the Stop-triggered
	// drain would run and we couldn't observe cache reuse.
	em.be.Stop(context.Background())
	em.be = newBatchEmitter(batchConfig{
		Name:          "sentinel",
		Flush:         em.flush,
		BatchSize:     1,
		FlushInterval: 20 * time.Millisecond,
		Logger:        quietLogger(),
	})

	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	time.Sleep(80 * time.Millisecond) // let several flush cycles run
	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "y"))
	time.Sleep(80 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = em.Stop(ctx)

	if d.ingestHits.Load() < 2 {
		t.Fatalf("expected >= 2 ingest hits across batches, got %d", d.ingestHits.Load())
	}
	if d.authHits.Load() != 1 {
		t.Errorf("auth hits = %d, want exactly 1 (token cache reused across flushes)", d.authHits.Load())
	}
}

func TestSentinelEmitterInvalidatesTokenOn401(t *testing.T) {
	d := newDual(t, http.StatusUnauthorized)
	defer d.close()
	em := newSentinelTestEmitter(t, d)

	em.be.Stop(context.Background())
	em.be = newBatchEmitter(batchConfig{
		Name:          "sentinel",
		Flush:         em.flush,
		BatchSize:     1,
		FlushInterval: 20 * time.Millisecond,
		Logger:        quietLogger(),
	})

	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "x"))
	time.Sleep(80 * time.Millisecond)
	em.Emit(context.Background(), audit.NewEvent(audit.DecisionAllow, "y"))
	time.Sleep(80 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = em.Stop(ctx)

	if d.authHits.Load() < 2 {
		t.Errorf("auth hits = %d, want >= 2 after 401s invalidate", d.authHits.Load())
	}
	if em.Status().LastError == "" {
		t.Error("expected LastError populated after 401")
	}
}
