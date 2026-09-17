package verify

import (
	"testing"
)

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"timeout error", &timeoutErr{msg: "i/o timeout"}, true},
		{"generic timeout", &timeoutErr{msg: "connection timeout"}, true},
		{"non-timeout", &timeoutErr{msg: "connection refused"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTimeout(tt.err)
			if got != tt.want {
				t.Errorf("isTimeout(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestWildcardOwner(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		sigLabels int
		want      string
	}{
		{
			"normal wildcard expansion",
			"_ati-identity._tls.www.ats-client.asia.",
			4,
			"*._tls.www.ats-client.asia.",
		},
		{
			"sigLabels equals owner labels",
			"example.com.",
			2,
			"example.com.", // no change
		},
		{
			"sigLabels greater than owner labels",
			"example.com.",
			5,
			"example.com.", // no change
		},
		{
			"single label wildcard",
			"sub.example.com.",
			2,
			"*.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wildcardOwner(tt.input, tt.sigLabels)
			if got != tt.want {
				t.Errorf("wildcardOwner(%q, %d) = %q, want %q", tt.input, tt.sigLabels, got, tt.want)
			}
		})
	}
}

func TestParentOf_EdgeCases(t *testing.T) {
	tests := []struct {
		zone string
		want string
	}{
		{".", "."},
		{"com.", "."},
		{"a", "."},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			got := parentOf(tt.zone)
			if got != tt.want {
				t.Errorf("parentOf(%q) = %q, want %q", tt.zone, got, tt.want)
			}
		})
	}
}

type timeoutErr struct {
	msg string
}

func (e *timeoutErr) Error() string { return e.msg }
