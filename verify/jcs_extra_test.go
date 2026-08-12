package verify

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
)

// TestJCSCanonicalize_NumberFormats targets jcsWriteNumber (lines 113-137)
// and es6NumberFormat (lines 143-174).
func TestJCSCanonicalize_NumberFormats(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Integer path (jcsWriteNumber integer branch)
		{"positive integer", `{"a":42}`, `{"a":42}`},
		{"zero", `{"a":0}`, `{"a":0}`},
		{"negative integer", `{"a":-42}`, `{"a":-42}`},
		{"large integer within safe range", `{"a":1000000}`, `{"a":1000000}`},
		{"one", `{"a":1}`, `{"a":1}`},
		{"negative one", `{"a":-1}`, `{"a":-1}`},
		// Float path: non-integer floats always render via ES6 scientific
		// notation (the implementation uses FormatFloat 'e' format), so
		// 1.5 -> "1.5e+0", not "1.5".
		//
		// 1.5e20 exceeds int64 range (~9.2e18), so it takes the ES6
		// scientific notation path. Per RFC 8785 §3.2.2.3 this is correct.
		{"very large float needing exponent", `{"a":1.5e20}`, `{"a":1.5e+20}`},
		{"very small float needing exponent", `{"a":0.000001}`, `{"a":1e-6}`},
		{"float with trailing zeros", `{"a":1.50}`, `{"a":1.5e+0}`},
		{"small non-integer float", `{"a":1.5}`, `{"a":1.5e+0}`},
		{"negative float", `{"a":-1.5}`, `{"a":-1.5e+0}`},
		{"float near integer boundary", `{"a":2.0}`, `{"a":2}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JCSCanonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("JCSCanonicalize(%q) error = %v", tt.input, err)
			}
			if string(got) != tt.want {
				t.Errorf("JCSCanonicalize(%q) = %q, want %q", tt.input, string(got), tt.want)
			}
		})
	}
}

// TestJCSCanonicalize_NullBooleanString targets the primitive branches in jcsWriteValue
// plus number formatting, exercising more of the canonicalize surface.
func TestJCSCanonicalize_NullBooleanString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"null value", `{"a":null}`, `{"a":null}`},
		{"boolean true", `{"a":true}`, `{"a":true}`},
		{"boolean false", `{"a":false}`, `{"a":false}`},
		{"string with unicode escape", `{"a":"é"}`, `{"a":"é"}`},
		{"string with backslash escape", `{"a":"a\\b"}`, `{"a":"a\\b"}`},
		{"string with quote escape", `{"a":"a\"b"}`, `{"a":"a\"b"}`},
		{"string with newline escape", `{"a":"a\nb"}`, `{"a":"a\nb"}`},
		{"plain string", `{"a":"hello"}`, `{"a":"hello"}`},
		{"empty string value", `{"a":""}`, `{"a":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JCSCanonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("JCSCanonicalize(%q) error = %v", tt.input, err)
			}
			if string(got) != tt.want {
				t.Errorf("JCSCanonicalize(%q) = %q, want %q", tt.input, string(got), tt.want)
			}
		})
	}
}

// TestJCSCanonicalize_NestedStructures targets array/object recursion.
func TestJCSCanonicalize_NestedStructures(t *testing.T) {
	t.Run("nested arrays", func(t *testing.T) {
		got, err := JCSCanonicalize([]byte(`[1, [2, 3]]`))
		if err != nil {
			t.Fatalf("JCSCanonicalize() error = %v", err)
		}
		want := `[1,[2,3]]`
		if string(got) != want {
			t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
		}
	})

	t.Run("nested objects unsorted keys", func(t *testing.T) {
		input := `{"c":{"b":1,"a":2},"a":3}`
		got, err := JCSCanonicalize([]byte(input))
		if err != nil {
			t.Fatalf("JCSCanonicalize() error = %v", err)
		}
		want := `{"a":3,"c":{"a":2,"b":1}}`
		if string(got) != want {
			t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
		}
	})

	t.Run("array with mixed types", func(t *testing.T) {
		got, err := JCSCanonicalize([]byte(`[null, true, false, 1, "x"]`))
		if err != nil {
			t.Fatalf("JCSCanonicalize() error = %v", err)
		}
		want := `[null,true,false,1,"x"]`
		if string(got) != want {
			t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
		}
	})

	t.Run("object with mixed number/string values", func(t *testing.T) {
		input := `{"num":3.14,"int":42,"str":"value","bool":true,"null":null}`
		got, err := JCSCanonicalize([]byte(input))
		if err != nil {
			t.Fatalf("JCSCanonicalize() error = %v", err)
		}
		// keys sorted; non-integer float uses 'e' format
		want := `{"bool":true,"int":42,"null":null,"num":3.14e+0,"str":"value"}`
		if string(got) != want {
			t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
		}
	})
}

// TestJCSCanonicalize_ExtraInvalidJSON confirms the error path returns an error
// for additional malformed inputs.
func TestJCSCanonicalize_ExtraInvalidJSON(t *testing.T) {
	cases := []string{
		`{invalid`,
		`[1,2,`,
		`{"a":}`,
		`{"a" "b"}`,
		``,
		`{`,
	}
	for _, in := range cases {
		t.Run(strconv.Quote(in), func(t *testing.T) {
			if _, err := JCSCanonicalize([]byte(in)); err == nil {
				t.Errorf("JCSCanonicalize(%q) expected error, got nil", in)
			}
		})
	}
}

// TestJcsWriteNumber_Direct directly exercises jcsWriteNumber for edge cases
// that may be hard to trigger through JCSCanonicalize alone.
func TestJcsWriteNumber_Direct(t *testing.T) {
	t.Run("integer zero", func(t *testing.T) {
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("0")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		if got := buf.String(); got != "0" {
			t.Errorf("jcsWriteNumber(0) = %q, want %q", got, "0")
		}
	})

	t.Run("negative zero", func(t *testing.T) {
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("-0")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		// f == 0 short-circuits to "0" before trunc check
		if got := buf.String(); got != "0" {
			t.Errorf("jcsWriteNumber(-0) = %q, want %q", got, "0")
		}
	})

	t.Run("positive integer", func(t *testing.T) {
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("12345")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		if got := buf.String(); got != "12345" {
			t.Errorf("jcsWriteNumber(12345) = %q, want %q", got, "12345")
		}
	})

	t.Run("negative integer", func(t *testing.T) {
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("-12345")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		if got := buf.String(); got != "-12345" {
			t.Errorf("jcsWriteNumber(-12345) = %q, want %q", got, "-12345")
		}
	})

	t.Run("small float", func(t *testing.T) {
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("1.5")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		// Non-integer floats use FormatFloat 'e' -> "1.5e+00", then
		// es6NumberFormat strips the leading zero in the exponent -> "1.5e+0".
		if got := buf.String(); got != "1.5e+0" {
			t.Errorf("jcsWriteNumber(1.5) = %q, want %q", got, "1.5e+0")
		}
	})

	t.Run("float whose magnitude triggers integer branch with int64 overflow", func(t *testing.T) {
		// 1.5e20 exceeds int64 range (~9.2e18), so the integer branch is NOT
		// taken; instead the ES6 scientific notation path applies (RFC 8785).
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("1.5e20")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		if got := buf.String(); got != "1.5e+20" {
			t.Errorf("jcsWriteNumber(1.5e20) = %q, want %q", got, "1.5e+20")
		}
	})

	t.Run("float needing negative exponent", func(t *testing.T) {
		var buf bytes.Buffer
		if err := jcsWriteNumber(&buf, json.Number("0.000001")); err != nil {
			t.Fatalf("jcsWriteNumber() error = %v", err)
		}
		if got := buf.String(); got != "1e-6" {
			t.Errorf("jcsWriteNumber(0.000001) = %q, want %q", got, "1e-6")
		}
	})

	t.Run("invalid number", func(t *testing.T) {
		var buf bytes.Buffer
		err := jcsWriteNumber(&buf, json.Number("not-a-number"))
		if err == nil {
			t.Error("jcsWriteNumber(invalid) expected error, got nil")
		}
	})
}

// TestEs6NumberFormat_Direct directly exercises es6NumberFormat branches.
func TestEs6NumberFormat_Direct(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no exponent", "1.5", "1.5"},
		{"positive exponent with plus", "1.5e+20", "1.5e+20"},
		{"positive exponent plus leading zeros", "1.5e+020", "1.5e+20"},
		{"negative exponent", "1.5e-6", "1.5e-6"},
		{"negative exponent with leading zeros", "1.5e-006", "1.5e-6"},
		// es6NumberFormat always rebuilds with lowercase 'e' (line 173), so a
		// capital 'E' in the input is normalized to 'e' in the output.
		{"capital E normalized to lowercase", "1.5E20", "1.5e20"},
		{"integer mantissa with exponent", "1e+20", "1e+20"},
		{"exponent zero", "1.5e+0", "1.5e+0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := es6NumberFormat(tt.in); got != tt.want {
				t.Errorf("es6NumberFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestJCSCanonicalizeFields_Cases targets JCSCanonicalizeFields (lines 31-48).
func TestJCSCanonicalizeFields_Cases(t *testing.T) {
	t.Run("single field", func(t *testing.T) {
		fields := map[string]json.RawMessage{
			"key": json.RawMessage(`"value"`),
		}
		got, err := JCSCanonicalizeFields(fields)
		if err != nil {
			t.Fatalf("JCSCanonicalizeFields() error = %v", err)
		}
		want := `{"key":"value"}`
		if string(got) != want {
			t.Errorf("JCSCanonicalizeFields() = %q, want %q", string(got), want)
		}
	})

	t.Run("multiple fields sorted keys", func(t *testing.T) {
		fields := map[string]json.RawMessage{
			"zebra":  json.RawMessage(`1`),
			"apple":  json.RawMessage(`2`),
			"mango":  json.RawMessage(`"fruit"`),
		}
		got, err := JCSCanonicalizeFields(fields)
		if err != nil {
			t.Fatalf("JCSCanonicalizeFields() error = %v", err)
		}
		want := `{"apple":2,"mango":"fruit","zebra":1}`
		if string(got) != want {
			t.Errorf("JCSCanonicalizeFields() = %q, want %q", string(got), want)
		}
	})

	t.Run("empty map", func(t *testing.T) {
		got, err := JCSCanonicalizeFields(map[string]json.RawMessage{})
		if err != nil {
			t.Fatalf("JCSCanonicalizeFields() error = %v", err)
		}
		want := `{}`
		if string(got) != want {
			t.Errorf("JCSCanonicalizeFields() = %q, want %q", string(got), want)
		}
	})

	t.Run("invalid JSON in field returns error", func(t *testing.T) {
		fields := map[string]json.RawMessage{
			"bad": json.RawMessage(`{invalid`),
		}
		_, err := JCSCanonicalizeFields(fields)
		if err == nil {
			t.Error("JCSCanonicalizeFields() expected error for invalid JSON field, got nil")
		}
	})

	t.Run("nested object value", func(t *testing.T) {
		fields := map[string]json.RawMessage{
			"b": json.RawMessage(`{"y":2,"x":1}`),
			"a": json.RawMessage(`[3,2,1]`),
		}
		got, err := JCSCanonicalizeFields(fields)
		if err != nil {
			t.Fatalf("JCSCanonicalizeFields() error = %v", err)
		}
		want := `{"a":[3,2,1],"b":{"x":1,"y":2}}`
		if string(got) != want {
			t.Errorf("JCSCanonicalizeFields() = %q, want %q", string(got), want)
		}
	})
}
