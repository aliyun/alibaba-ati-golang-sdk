package ati

import "testing"

func TestTrustLevel_String(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  string
	}{
		{PKIOnly, "PKI_ONLY"},
		{BadgeRequired, "BADGE_REQUIRED"},
		{DANEAndBadge, "DANE_AND_BADGE"},
		{TrustLevel(99), "TrustLevel(99)"},
		{TrustLevel(-1), "TrustLevel(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.level.String()
			if got != tt.want {
				t.Errorf("TrustLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestTrustLevel_Constants(t *testing.T) {
	if PKIOnly != 0 {
		t.Errorf("PKIOnly = %d, want 0", PKIOnly)
	}
	if BadgeRequired != 1 {
		t.Errorf("BadgeRequired = %d, want 1", BadgeRequired)
	}
	if DANEAndBadge != 2 {
		t.Errorf("DANEAndBadge = %d, want 2", DANEAndBadge)
	}
}

func TestTrustLevel_Aliases(t *testing.T) {
	if TrustNone != PKIOnly {
		t.Errorf("TrustNone = %d, want %d (PKIOnly)", TrustNone, PKIOnly)
	}
	if TrustPKI != PKIOnly {
		t.Errorf("TrustPKI = %d, want %d (PKIOnly)", TrustPKI, PKIOnly)
	}
	if TrustBadge != BadgeRequired {
		t.Errorf("TrustBadge = %d, want %d (BadgeRequired)", TrustBadge, BadgeRequired)
	}
	if TrustFull != DANEAndBadge {
		t.Errorf("TrustFull = %d, want %d (DANEAndBadge)", TrustFull, DANEAndBadge)
	}
	if Bronze != PKIOnly {
		t.Errorf("Bronze = %d, want %d (PKIOnly)", Bronze, PKIOnly)
	}
	if Silver != BadgeRequired {
		t.Errorf("Silver = %d, want %d (BadgeRequired)", Silver, BadgeRequired)
	}
	if Gold != DANEAndBadge {
		t.Errorf("Gold = %d, want %d (DANEAndBadge)", Gold, DANEAndBadge)
	}
}

func TestTrustLevel_ValidForClient(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  bool
	}{
		{PKIOnly, true},
		{BadgeRequired, true},
		{DANEAndBadge, true},
		{TrustLevel(-1), false},
		{TrustLevel(99), false},
	}
	for _, tt := range tests {
		if got := tt.level.ValidForClient(); got != tt.want {
			t.Errorf("%s.ValidForClient() = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestTrustLevel_ValidForServer(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  bool
	}{
		{PKIOnly, true},
		{BadgeRequired, true},
		{DANEAndBadge, true},
		{TrustLevel(-1), false},
		{TrustLevel(99), false},
	}
	for _, tt := range tests {
		if got := tt.level.ValidForServer(); got != tt.want {
			t.Errorf("%s.ValidForServer() = %v, want %v", tt.level, got, tt.want)
		}
	}
}
