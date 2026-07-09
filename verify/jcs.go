package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
)

// JCSCanonicalize performs JSON Canonicalization per RFC 8785.
// It parses the input JSON and re-serializes it with sorted object keys,
// no whitespace, and ES6-compliant number formatting.
func JCSCanonicalize(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: failed to parse JSON: %w", err)
	}
	var buf bytes.Buffer
	if err := jcsWriteValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// JCSCanonicalizeFields builds a canonical JSON object from the given key-value
// pairs (where values are raw JSON bytes), sorts keys, and returns the result.
func JCSCanonicalizeFields(fields map[string]json.RawMessage) ([]byte, error) {
	parsed := make(map[string]any, len(fields))
	for k, raw := range fields {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("jcs: failed to parse field %q: %w", k, err)
		}
		parsed[k] = v
	}

	var buf bytes.Buffer
	if err := jcsWriteValue(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func jcsWriteValue(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("jcs: failed to encode string: %w", err)
		}
		buf.Write(encoded)
	case json.Number:
		if err := jcsWriteNumber(buf, val); err != nil {
			return err
		}
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsWriteValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			if first {
				first = false
			} else {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("jcs: failed to encode key %q: %w", k, err)
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := jcsWriteValue(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

// jcsWriteNumber formats a number per ES6 Number.toString() (RFC 8785 §3.2.2.3).
func jcsWriteNumber(buf *bytes.Buffer, n json.Number) error {
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("jcs: invalid number %q: %w", n.String(), err)
	}

	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("jcs: NaN and Infinity are not valid JSON numbers")
	}

	if f == 0 {
		buf.WriteByte('0')
		return nil
	}

	// Integer check: if the float64 is an exact integer and within safe range
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}

	// ES6 Number.toString uses shortest representation with lowercase 'e'
	s := strconv.FormatFloat(f, 'e', -1, 64)
	buf.WriteString(es6NumberFormat(s))
	return nil
}

// es6NumberFormat converts Go's scientific notation to ES6 format.
// Go produces "1.5e+02", ES6 wants "1.5e+2" (no leading zero in exponent unless needed).
// Go produces "-0" for negative zero, ES6 wants "0".
func es6NumberFormat(s string) string {
	idx := -1
	for i, c := range s {
		if c == 'e' || c == 'E' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s
	}

	mantissa := s[:idx]
	exp := s[idx+1:]

	// Parse exponent, strip leading zeros
	sign := ""
	if exp[0] == '+' || exp[0] == '-' {
		sign = string(exp[0])
		exp = exp[1:]
	}

	// Remove leading zeros from exponent
	expVal, _ := strconv.Atoi(exp)
	expStr := strconv.Itoa(expVal)

	if sign == "+" {
		sign = "+"
	}

	return mantissa + "e" + sign + expStr
}
