package ati

import "testing"

func TestTrustLevel_String(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  string
	}{
		{TrustNone, "None"},
		{TrustPKI, "PKI"},
		{TrustBadge, "Badge"},
		{TrustFull, "Full"},
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
	if TrustNone != 0 {
		t.Errorf("TrustNone = %d, want 0", TrustNone)
	}
	if TrustPKI != 1 {
		t.Errorf("TrustPKI = %d, want 1", TrustPKI)
	}
	if TrustBadge != 2 {
		t.Errorf("TrustBadge = %d, want 2", TrustBadge)
	}
	if TrustFull != 3 {
		t.Errorf("TrustFull = %d, want 3", TrustFull)
	}
}

func TestTrustLevel_Aliases(t *testing.T) {
	if Bronze != TrustPKI {
		t.Errorf("Bronze = %d, want %d (TrustPKI)", Bronze, TrustPKI)
	}
	if Silver != TrustBadge {
		t.Errorf("Silver = %d, want %d (TrustBadge)", Silver, TrustBadge)
	}
	if Gold != TrustFull {
		t.Errorf("Gold = %d, want %d (TrustFull)", Gold, TrustFull)
	}
}

func TestTrustLevel_ValidForClient(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  bool
	}{
		{TrustNone, false},
		{TrustPKI, true},
		{TrustBadge, true},
		{TrustFull, true},
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
		{TrustNone, true},
		{TrustPKI, false},
		{TrustBadge, true},
		{TrustFull, true},
	}
	for _, tt := range tests {
		if got := tt.level.ValidForServer(); got != tt.want {
			t.Errorf("%s.ValidForServer() = %v, want %v", tt.level, got, tt.want)
		}
	}
}
