package ati

import (
	"fmt"
	"testing"
)

func TestVerificationPolicy_String(t *testing.T) {
	tests := []struct {
		policy VerificationPolicy
		want   string
	}{
		{PolicyPKI, "PKI"},
		{PolicyPKIBadge, "PKIBadge"},
		{PolicyPKIBadgeDANE, "PKIBadgeDANE"},
		{VerificationPolicy(99), "VerificationPolicy(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.policy.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerificationPolicy_Constants(t *testing.T) {
	if PolicyPKI != 0 {
		t.Errorf("PolicyPKI = %d, want 0", PolicyPKI)
	}
	if PolicyPKIBadge != 1 {
		t.Errorf("PolicyPKIBadge = %d, want 1", PolicyPKIBadge)
	}
	if PolicyPKIBadgeDANE != 2 {
		t.Errorf("PolicyPKIBadgeDANE = %d, want 2", PolicyPKIBadgeDANE)
	}
}

func TestVerificationPolicy_String_UnknownValues(t *testing.T) {
	for _, v := range []int{-1, 5, 100} {
		p := VerificationPolicy(v)
		expected := fmt.Sprintf("VerificationPolicy(%d)", v)
		if p.String() != expected {
			t.Errorf("VerificationPolicy(%d).String() = %q, want %q", v, p.String(), expected)
		}
	}
}
