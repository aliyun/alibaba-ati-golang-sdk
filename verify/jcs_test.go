package verify

import (
	"encoding/json"
	"testing"
)

func TestJCSCanonicalize_SimpleObject(t *testing.T) {
	input := `{"b": "2", "a": "1"}`
	got, err := JCSCanonicalize([]byte(input))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	want := `{"a":"1","b":"2"}`
	if string(got) != want {
		t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
	}
}

func TestJCSCanonicalize_NestedObject(t *testing.T) {
	input := `{"z": {"b": 2, "a": 1}, "a": "hello"}`
	got, err := JCSCanonicalize([]byte(input))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	want := `{"a":"hello","z":{"a":1,"b":2}}`
	if string(got) != want {
		t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
	}
}

func TestJCSCanonicalize_Array(t *testing.T) {
	input := `[3, 1, 2]`
	got, err := JCSCanonicalize([]byte(input))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	want := `[3,1,2]`
	if string(got) != want {
		t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
	}
}

func TestJCSCanonicalize_Primitives(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"null", `null`, `null`},
		{"true", `true`, `true`},
		{"false", `false`, `false`},
		{"string", `"hello"`, `"hello"`},
		{"integer", `42`, `42`},
		{"negative integer", `-1`, `-1`},
		{"zero", `0`, `0`},
		{"string with escapes", `"a\"b\\c"`, `"a\"b\\c"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JCSCanonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("JCSCanonicalize() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("JCSCanonicalize() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestJCSCanonicalize_EmptyStructures(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty object", `{}`, `{}`},
		{"empty array", `[]`, `[]`},
		{"empty string", `""`, `""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JCSCanonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("JCSCanonicalize() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("JCSCanonicalize() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestJCSCanonicalize_WhitespaceRemoved(t *testing.T) {
	input := `{
		"key" : "value" ,
		"array" : [ 1 , 2 , 3 ]
	}`
	got, err := JCSCanonicalize([]byte(input))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	want := `{"array":[1,2,3],"key":"value"}`
	if string(got) != want {
		t.Errorf("JCSCanonicalize() = %q, want %q", string(got), want)
	}
}

func TestJCSCanonicalize_Idempotent(t *testing.T) {
	input := `{"a":"1","b":{"c":3}}`
	first, err := JCSCanonicalize([]byte(input))
	if err != nil {
		t.Fatalf("first JCSCanonicalize() error = %v", err)
	}
	second, err := JCSCanonicalize(first)
	if err != nil {
		t.Fatalf("second JCSCanonicalize() error = %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("JCS not idempotent: %q vs %q", string(first), string(second))
	}
}

func TestJCSCanonicalize_InvalidJSON(t *testing.T) {
	_, err := JCSCanonicalize([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestJCSCanonicalize_TLResponseLike(t *testing.T) {
	input := `{
		"status": "ACTIVE",
		"schemaVersion": "v1",
		"payload": {
			"agentName": "test-agent",
			"agentHost": "example.com",
			"agentId": "ag-123",
			"agentStatus": "ACTIVE"
		},
		"evidenceRef": {
			"evidenceId": "ev-1",
			"evidenceType": "registration"
		}
	}`
	got, err := JCSCanonicalize([]byte(input))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}

	// Keys should be sorted at each level
	want := `{"evidenceRef":{"evidenceId":"ev-1","evidenceType":"registration"},"payload":{"agentHost":"example.com","agentId":"ag-123","agentName":"test-agent","agentStatus":"ACTIVE"},"schemaVersion":"v1","status":"ACTIVE"}`
	if string(got) != want {
		t.Errorf("JCSCanonicalize() = %q,\nwant %q", string(got), want)
	}
}

func TestJCSCanonicalizeFields(t *testing.T) {
	fields := map[string]json.RawMessage{
		"status":        json.RawMessage(`"ACTIVE"`),
		"schemaVersion": json.RawMessage(`"v1"`),
	}

	got, err := JCSCanonicalizeFields(fields)
	if err != nil {
		t.Fatalf("JCSCanonicalizeFields() error = %v", err)
	}
	want := `{"schemaVersion":"v1","status":"ACTIVE"}`
	if string(got) != want {
		t.Errorf("JCSCanonicalizeFields() = %q, want %q", string(got), want)
	}
}
