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
		{PolicyNone, "None"},
		{PolicyPKIOnly, "PKIOnly"},
		{PolicyBadgeRequired, "BadgeRequired"},
		{PolicyFull, "Full"},
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
	if PolicyNone != 0 {
		t.Errorf("PolicyNone = %d, want 0", PolicyNone)
	}
	if PolicyPKIOnly != 1 {
		t.Errorf("PolicyPKIOnly = %d, want 1", PolicyPKIOnly)
	}
	if PolicyBadgeRequired != 2 {
		t.Errorf("PolicyBadgeRequired = %d, want 2", PolicyBadgeRequired)
	}
	if PolicyFull != 3 {
		t.Errorf("PolicyFull = %d, want 3", PolicyFull)
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
