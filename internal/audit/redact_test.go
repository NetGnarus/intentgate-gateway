package audit

import (
	"reflect"
	"testing"
)

func TestParseRedactionMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    RedactionMode
		wantErr bool
	}{
		{"", RedactOff, false},
		{"off", RedactOff, false},
		{"OFF", RedactOff, false},
		{"none", RedactOff, false},
		{"false", RedactOff, false},
		{"0", RedactOff, false},
		{"scalars", RedactScalars, false},
		{"Scalar", RedactScalars, false},
		{"numbers", RedactScalars, false},
		{"raw", RedactRaw, false},
		{"all", RedactRaw, false},
		{"values", RedactRaw, false},
		{"yes", RedactOff, true},
		{"unknown-mode", RedactOff, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseRedactionMode(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("ParseRedactionMode(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestRedactArgsOffReturnsNil(t *testing.T) {
	t.Parallel()
	in := map[string]any{"amount_eur": 1500, "recipient": "Acme"}
	if got := RedactArgs(in, RedactOff); got != nil {
		t.Errorf("RedactOff should return nil, got %v", got)
	}
}

func TestRedactArgsRawDeepCopies(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"amount_eur": 1500,
		"recipient":  "Acme",
		"items":      []any{map[string]any{"sku": "A"}},
	}
	out := RedactArgs(in, RedactRaw)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("RedactRaw should preserve values; got %v want %v", out, in)
	}
	// Mutating the output must not touch the input.
	out["amount_eur"] = 9999
	if in["amount_eur"] != 1500 {
		t.Error("RedactRaw must deep-copy; input was mutated through output")
	}
	outItems := out["items"].([]any)
	outItems[0].(map[string]any)["sku"] = "MUTATED"
	if in["items"].([]any)[0].(map[string]any)["sku"] != "A" {
		t.Error("RedactRaw must deep-copy nested structures")
	}
}

func TestRedactArgsScalarsPolicy(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"amount_eur":  1500,
		"urgent":      true,
		"approved":    false,
		"recipient":   "Acme Co",
		"memo":        "Q3 invoice",
		"items":       []any{map[string]any{"sku": "A", "qty": 5}, map[string]any{"sku": "B", "qty": 3}},
		"missing":     nil,
		"big_amount":  float64(1234567.89),
		"signed_int":  int64(-42),
		"unsupported": struct{ X int }{X: 1}, // unknown type → nil
	}
	out := RedactArgs(in, RedactScalars)

	// Scalars preserved.
	if out["amount_eur"] != 1500 {
		t.Errorf("amount_eur should be preserved, got %v", out["amount_eur"])
	}
	if out["urgent"] != true || out["approved"] != false {
		t.Errorf("bools should be preserved, got urgent=%v approved=%v", out["urgent"], out["approved"])
	}
	if out["big_amount"] != float64(1234567.89) {
		t.Errorf("float64 not preserved, got %v", out["big_amount"])
	}
	if out["signed_int"] != int64(-42) {
		t.Errorf("int64 not preserved, got %v", out["signed_int"])
	}
	if out["missing"] != nil {
		t.Errorf("nil should be preserved, got %v", out["missing"])
	}

	// Strings dropped.
	if out["recipient"] != nil {
		t.Errorf("string recipient should be nil, got %v", out["recipient"])
	}
	if out["memo"] != nil {
		t.Errorf("string memo should be nil, got %v", out["memo"])
	}

	// Nested structures preserved structurally, with leaf strings redacted.
	items, ok := out["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items should be a 2-element slice, got %T %v", out["items"], out["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("items[0] should be a map, got %T", items[0])
	}
	if first["sku"] != nil {
		t.Errorf("nested string sku should be redacted, got %v", first["sku"])
	}
	if first["qty"] != 5 {
		t.Errorf("nested int qty should be preserved, got %v", first["qty"])
	}

	// Unknown types drop to nil rather than passing through.
	if out["unsupported"] != nil {
		t.Errorf("unknown struct type should drop to nil, got %v", out["unsupported"])
	}
}

func TestRedactArgsNilInput(t *testing.T) {
	t.Parallel()
	for _, mode := range []RedactionMode{RedactOff, RedactScalars, RedactRaw} {
		if got := RedactArgs(nil, mode); got != nil {
			t.Errorf("nil input must always return nil; mode=%v got=%v", mode, got)
		}
	}
}

func TestRedactArgsScalarsDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	nested := map[string]any{"sku": "A", "qty": 5}
	in := map[string]any{"items": []any{nested}}
	out := RedactArgs(in, RedactScalars)

	// Mutate output, original must stay intact.
	out["items"].([]any)[0].(map[string]any)["qty"] = 999
	if nested["qty"] != 5 {
		t.Error("scalar redaction must not share references with input")
	}
}
