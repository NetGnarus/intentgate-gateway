package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RedactionMode controls how the gateway persists tool-call argument
// values onto an audit event's [Event.ArgValues] field.
//
// The mode is deliberately a small enum rather than a free-form policy
// because audit-log privacy is a single big design knob, not a
// composition of small ones — every mode here is one of "I trust the
// audit log with X" answers.
type RedactionMode int

const (
	// RedactOff is the default: do not populate ArgValues at all.
	// Audit events retain only [Event.ArgKeys] (the keys), preserving
	// the privacy posture customers had on gateway versions 1.0-1.2:
	// argument values never enter the audit log under any
	// circumstance. Dry-run cannot validate value-threshold rules in
	// this mode; the operator gets a static-source warning.
	RedactOff RedactionMode = iota

	// RedactScalars preserves number, boolean, and null arg values
	// verbatim. String values, arrays, and objects are replaced with
	// nil. This is the recommended mode for customers who want
	// faithful dry-run replay of numeric-threshold and boolean-flag
	// rules without ever logging free-form text that could carry PII.
	// Examples of what survives in the audit log:
	//   {amount_eur: 1500, urgent: true, batch_id: 42}  → preserved verbatim
	//   {recipient: "Acme Co", memo: "Q3 invoice 1142"} → both nil
	//   {items: [{sku: "A", qty: 5}, {sku: "B", qty: 3}]} → [{sku: nil, qty: 5}, ...]
	RedactScalars

	// RedactRaw persists argument values verbatim. INTENDED FOR
	// INTERNAL / TRUSTED DEPLOYMENTS ONLY. Customers running this in
	// regulated environments will likely violate their own data-
	// minimization commitments; we ship it because some local-dev,
	// pre-production, and air-gapped deployments do want full
	// fidelity. Not the default and never enabled implicitly.
	RedactRaw
)

// String returns the env-var-friendly name for the mode. Inverse of
// [ParseRedactionMode]; the two stay in lockstep.
func (m RedactionMode) String() string {
	switch m {
	case RedactOff:
		return "off"
	case RedactScalars:
		return "scalars"
	case RedactRaw:
		return "raw"
	default:
		return "off"
	}
}

// ParseRedactionMode reads an env-var value into a RedactionMode.
// Recognised inputs: "" / "off" / "false" / "0" → Off; "scalars" →
// Scalars; "raw" / "all" → Raw. Anything else is an error so the
// gateway fails fast on a misconfigured value rather than silently
// downgrading to Off.
func ParseRedactionMode(raw string) (RedactionMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off", "false", "0", "none":
		return RedactOff, nil
	case "scalars", "scalar", "numbers":
		return RedactScalars, nil
	case "raw", "all", "values":
		return RedactRaw, nil
	default:
		return RedactOff, fmt.Errorf(
			"unknown INTENTGATE_AUDIT_PERSIST_ARG_VALUES=%q (want off|scalars|raw)", raw,
		)
	}
}

// RedactArgs returns a map suitable for assignment to
// [Event.ArgValues], applying the policy of mode.
//
// The function is value-pure: input is never mutated. Output is a
// freshly allocated structure even when mode is [RedactRaw], because
// the audit emitter may run asynchronously and the caller is free to
// mutate the original args after Emit returns.
//
// nil input returns nil regardless of mode (no fake-key noise).
func RedactArgs(args map[string]any, mode RedactionMode) map[string]any {
	if args == nil {
		return nil
	}
	switch mode {
	case RedactOff:
		return nil
	case RedactRaw:
		return cloneMap(args)
	case RedactScalars:
		out := make(map[string]any, len(args))
		for k, v := range args {
			out[k] = redactScalarValue(v)
		}
		return out
	}
	return nil
}

// redactScalarValue applies the [RedactScalars] policy to a single
// value. Numbers, booleans, and nulls are preserved verbatim. Strings
// are replaced with nil — string-shaped data is the most common PII
// vector (recipient names, memo lines, addresses, IDs). Arrays and
// objects recurse so a nested numeric threshold like
// {items[0].qty > 100} still works.
func redactScalarValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return x
	case int, int32, int64, uint, uint32, uint64,
		float32, float64,
		json.Number: // tolerated; some upstream codepaths preserve number-as-string.
		return x
	case string:
		// Strings are the headline PII vector. Drop unconditionally.
		// Length is not preserved — even length leaks (e.g. 16-char
		// strings are almost always credit-card numbers).
		return nil
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactScalarValue(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = redactScalarValue(vv)
		}
		return out
	default:
		// Unknown shape (could be a typed numeric the standard
		// library hasn't surfaced, or a json.RawMessage). Be
		// conservative and drop.
		return nil
	}
}

// cloneMap deep-copies a map[string]any so the emitter never holds a
// pointer into the caller's mutable data. Sub-types we recurse into:
// nested maps and []any slices. Other reference types (json.RawMessage,
// typed structs) are passed through — at this level we're only
// guarding against the common JSON-decoded shape, not every Go type a
// caller could theoretically hand us.
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return v
	}
}
