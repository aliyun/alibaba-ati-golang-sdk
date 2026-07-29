package ati

import "testing"

func TestVerificationPolicy_String(t *testing.T) {
	tests := []struct {
		level VerificationPolicy
		want  string
	}{
		{PolicyNone, "NONE"},
		{PolicyBasic, "BASIC"},
		{PolicyEnhanced, "ENHANCED"},
		{PolicyAdvanced, "ADVANCED"},
		{VerificationPolicy(99), "VerificationPolicy(99)"},
		{VerificationPolicy(-1), "VerificationPolicy(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.level.String()
			if got != tt.want {
				t.Errorf("VerificationPolicy(%d).String() = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestVerificationPolicy_Constants(t *testing.T) {
	if PolicyNone != 0 {
		t.Errorf("PolicyNone = %d, want 0", PolicyNone)
	}
	if PolicyBasic != 1 {
		t.Errorf("PolicyBasic = %d, want 1", PolicyBasic)
	}
	if PolicyEnhanced != 2 {
		t.Errorf("PolicyEnhanced = %d, want 2", PolicyEnhanced)
	}
	if PolicyAdvanced != 3 {
		t.Errorf("PolicyAdvanced = %d, want 3", PolicyAdvanced)
	}
}

func TestTrustLevel_DeprecatedAliases(t *testing.T) {
	if PKIOnly != PolicyBasic {
		t.Errorf("PKIOnly = %d, want %d (PolicyBasic)", PKIOnly, PolicyBasic)
	}
	if BadgeRequired != PolicyEnhanced {
		t.Errorf("BadgeRequired = %d, want %d (PolicyEnhanced)", BadgeRequired, PolicyEnhanced)
	}
	if DANEAndBadge != PolicyAdvanced {
		t.Errorf("DANEAndBadge = %d, want %d (PolicyAdvanced)", DANEAndBadge, PolicyAdvanced)
	}
	if TrustNone != PolicyBasic {
		t.Errorf("TrustNone = %d, want %d (PolicyBasic)", TrustNone, PolicyBasic)
	}
	if TrustPKI != PolicyBasic {
		t.Errorf("TrustPKI = %d, want %d (PolicyBasic)", TrustPKI, PolicyBasic)
	}
	if TrustBadge != PolicyEnhanced {
		t.Errorf("TrustBadge = %d, want %d (PolicyEnhanced)", TrustBadge, PolicyEnhanced)
	}
	if TrustFull != PolicyAdvanced {
		t.Errorf("TrustFull = %d, want %d (PolicyAdvanced)", TrustFull, PolicyAdvanced)
	}
	if Bronze != PolicyBasic {
		t.Errorf("Bronze = %d, want %d (PolicyBasic)", Bronze, PolicyBasic)
	}
	if Silver != PolicyEnhanced {
		t.Errorf("Silver = %d, want %d (PolicyEnhanced)", Silver, PolicyEnhanced)
	}
	if Gold != PolicyAdvanced {
		t.Errorf("Gold = %d, want %d (PolicyAdvanced)", Gold, PolicyAdvanced)
	}
}

func TestVerificationPolicy_ValidForClient(t *testing.T) {
	tests := []struct {
		level VerificationPolicy
		want  bool
	}{
		{PolicyNone, true},
		{PolicyBasic, true},
		{PolicyEnhanced, true},
		{PolicyAdvanced, true},
		{VerificationPolicy(-1), false},
		{VerificationPolicy(99), false},
	}
	for _, tt := range tests {
		if got := tt.level.ValidForClient(); got != tt.want {
			t.Errorf("%s.ValidForClient() = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestVerificationPolicy_ValidForServer(t *testing.T) {
	tests := []struct {
		level VerificationPolicy
		want  bool
	}{
		{PolicyNone, true},
		{PolicyBasic, true},
		{PolicyEnhanced, true},
		{PolicyAdvanced, true},
		{VerificationPolicy(-1), false},
		{VerificationPolicy(99), false},
	}
	for _, tt := range tests {
		if got := tt.level.ValidForServer(); got != tt.want {
			t.Errorf("%s.ValidForServer() = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestVerificationPolicy_DisplayName(t *testing.T) {
	tests := []struct {
		level VerificationPolicy
		want  string
	}{
		{PolicyNone, "L0 None"},
		{PolicyBasic, "L1 Basic"},
		{PolicyEnhanced, "L2 Enhanced"},
		{PolicyAdvanced, "L3 Advanced"},
	}
	for _, tt := range tests {
		if got := tt.level.DisplayName(); got != tt.want {
			t.Errorf("%s.DisplayName() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestVerificationPolicy_HasBadgeVerification(t *testing.T) {
	tests := []struct {
		level VerificationPolicy
		want  bool
	}{
		{PolicyNone, false},
		{PolicyBasic, false},
		{PolicyEnhanced, true},
		{PolicyAdvanced, true},
	}
	for _, tt := range tests {
		if got := tt.level.HasBadgeVerification(); got != tt.want {
			t.Errorf("%s.HasBadgeVerification() = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestVerificationPolicy_HasDANEVerification(t *testing.T) {
	tests := []struct {
		level VerificationPolicy
		want  bool
	}{
		{PolicyNone, false},
		{PolicyBasic, false},
		{PolicyEnhanced, false},
		{PolicyAdvanced, true},
	}
	for _, tt := range tests {
		if got := tt.level.HasDANEVerification(); got != tt.want {
			t.Errorf("%s.HasDANEVerification() = %v, want %v", tt.level, got, tt.want)
		}
	}
}
