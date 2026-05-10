package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Event shape ---------------------------------------------------------

func TestNewEventPopulatesDefaults(t *testing.T) {
	e := NewEvent(DecisionAllow, "read_invoice")
	if e.Decision != DecisionAllow {
		t.Errorf("decision: %v", e.Decision)
	}
	if e.Tool != "read_invoice" {
		t.Errorf("tool: %v", e.Tool)
	}
	if e.EventName != "intentgate.tool_call" {
		t.Errorf("event name: %v", e.EventName)
	}
	if e.SchemaVersion != "4" {
		t.Errorf("schema version: %v", e.SchemaVersion)
	}
	// Timestamp must parse back to within one second of now.
	parsed, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	if time.Since(parsed) > time.Second {
		t.Errorf("timestamp too far in the past: %s", e.Timestamp)
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	orig := Event{
		Timestamp:         "2026-05-08T22:00:00Z",
		EventName:         "intentgate.tool_call",
		SchemaVersion:     "1",
		Decision:          DecisionBlock,
		Check:             CheckPolicy,
		Reason:            "transfer above threshold",
		AgentID:           "finance-copilot-v3",
		SessionID:         "sess_abc",
		Tool:              "transfer_funds",
		ArgKeys:           []string{"amount_eur", "recipient"},
		CapabilityTokenID: "cap_01HXY",
		IntentSummary:     "Pay vendor invoice",
		LatencyMS:         5,
		RemoteIP:          "127.0.0.1:1234",
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity-check the JSON contains the SIEM-friendly field names.
	for _, want := range []string{
		`"ts":"2026-05-08T22:00:00Z"`,
		`"event":"intentgate.tool_call"`,
		`"schema_version":"1"`,
		`"decision":"block"`,
		`"check":"policy"`,
		`"agent_id":"finance-copilot-v3"`,
		`"tool":"transfer_funds"`,
		`"arg_keys":["amount_eur","recipient"]`,
		`"capability_token_id":"cap_01HXY"`,
		`"intent_summary":"Pay vendor invoice"`,
		`"latency_ms":5`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON missing %q in: %s", want, raw)
		}
	}

	// Round-trip back through Unmarshal. Event has a []string field, so
	// the type is not comparable with == (Go checks comparability
	// statically by type, not by whether the slice value is nil).
	// reflect.DeepEqual handles slices correctly.
	var got Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, orig) {
		t.Errorf("round-trip drift:\n  got=%+v\n  orig=%+v", got, orig)
	}
}

func TestEventOmitsEmptyOptionals(t *testing.T) {
	// An allow with no agent / session / token / intent — for example,
	// dev mode — should produce a tight JSON line without empty strings
	// for those fields.
	e := NewEvent(DecisionAllow, "read_invoice")
	raw, _ := json.Marshal(e)
	for _, unwanted := range []string{
		`"check":""`,
		`"agent_id":""`,
		`"session_id":""`,
		`"capability_token_id":""`,
		`"intent_summary":""`,
		`"remote_ip":""`,
	} {
		if strings.Contains(string(raw), unwanted) {
			t.Errorf("expected omitempty to drop %q, got: %s", unwanted, raw)
		}
	}
}

// --- StdoutEmitter -------------------------------------------------------

func TestStdoutEmitterWritesOneJSONLineEach(t *testing.T) {
	var buf bytes.Buffer
	em := NewWriterEmitter(&buf)

	em.Emit(context.Background(), NewEvent(DecisionAllow, "read_invoice"))
	em.Emit(context.Background(), Event{
		Timestamp: "2026-05-08T22:00:01Z",
		EventName: "intentgate.tool_call",
		Decision:  DecisionBlock,
		Check:     CheckBudget,
		Tool:      "read_invoice",
		Reason:    "max_calls exceeded",
		LatencyMS: 1,
	})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d not valid JSON: %v\n  %s", i, err, line)
		}
	}
}

func TestStdoutEmitterIsSafeForConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	em := NewWriterEmitter(&buf)

	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			em.Emit(context.Background(), NewEvent(DecisionAllow, "read_invoice"))
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != N {
		t.Fatalf("expected %d lines, got %d", N, len(lines))
	}
	// Every line is a complete JSON object — concurrent writers didn't
	// interleave each other.
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d corrupted: %v", i, err)
		}
	}
}

func TestNullEmitterDoesNothing(t *testing.T) {
	em := NewNullEmitter()
	// Just calling Emit must not panic and must not require a buffer.
	em.Emit(context.Background(), NewEvent(DecisionAllow, "x"))
}

// --- FromTarget ----------------------------------------------------------

func TestFromTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantDesc string
		wantErr  bool
	}{
		{"", "stdout", false},
		{"stdout", "stdout", false},
		{"none", "none", false},
		{"off", "none", false},
		{"kafka", "", true},
		{"file:/var/log/intentgate.log", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			em, desc, err := FromTarget(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && em == nil {
				t.Errorf("nil emitter on success")
			}
			if !tc.wantErr && desc != tc.wantDesc {
				t.Errorf("desc=%q want %q", desc, tc.wantDesc)
			}
		})
	}
}
