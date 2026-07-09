package verify

import (
	"errors"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestOutcomeConstructors(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
		},
	}
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})

	tests := []struct {
		name      string
		outcome   *VerificationOutcome
		wantType  OutcomeType
		isSuccess bool
	}{
		{
			name:      "verified outcome",
			outcome:   NewVerifiedOutcome(tlResp, fp),
			wantType:  OutcomeVerified,
			isSuccess: true,
		},
		{
			name:      "not ANS agent",
			outcome:   NewNotATIAgentOutcome("test.example.com"),
			wantType:  OutcomeNotATIAgent,
			isSuccess: false,
		},
		{
			name:      "invalid status",
			outcome:   NewInvalidStatusOutcome(tlResp, models.TLStatusRevoked),
			wantType:  OutcomeInvalidStatus,
			isSuccess: false,
		},
		{
			name:      "fingerprint mismatch",
			outcome:   NewFingerprintMismatchOutcome(tlResp, "SHA256:expected", "SHA256:actual"),
			wantType:  OutcomeFingerprintMismatch,
			isSuccess: false,
		},
		{
			name:      "hostname mismatch",
			outcome:   NewHostnameMismatchOutcome(tlResp, "foo.com", "bar.com"),
			wantType:  OutcomeHostnameMismatch,
			isSuccess: false,
		},
		{
			name:      "ATI name mismatch",
			outcome:   NewATINameMismatchOutcome(tlResp, "ati://v1.0.0.foo.com", "ati://v2.0.0.foo.com"),
			wantType:  OutcomeATINameMismatch,
			isSuccess: false,
		},
		{
			name:      "DNS error",
			outcome:   NewDNSErrorOutcome(errors.New("dns failed")),
			wantType:  OutcomeDNSError,
			isSuccess: false,
		},
		{
			name:      "tlog error",
			outcome:   NewTlogErrorOutcome(errors.New("tlog failed")),
			wantType:  OutcomeTlogError,
			isSuccess: false,
		},
		{
			name:      "cert error",
			outcome:   NewCertErrorOutcome(errors.New("cert failed")),
			wantType:  OutcomeCertError,
			isSuccess: false,
		},
		{
			name:      "fail open",
			outcome:   NewFailOpenOutcome(errors.New("underlying error")),
			wantType:  OutcomeFailOpen,
			isSuccess: true,
		},
		{
			name: "DANE rejection",
			outcome: NewDANERejectionOutcome(tlResp, &DANEOutcome{
				Type:  DANEMismatch,
				Error: errors.New("DANE mismatch"),
			}),
			wantType:  OutcomeDANERejection,
			isSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.outcome.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", tt.outcome.Type, tt.wantType)
			}
			if tt.outcome.IsSuccess() != tt.isSuccess {
				t.Errorf("IsSuccess() = %v, want %v", tt.outcome.IsSuccess(), tt.isSuccess)
			}
		})
	}
}

func TestOutcome_IsFailOpen(t *testing.T) {
	failOpen := NewFailOpenOutcome(nil)
	if !failOpen.IsFailOpen() {
		t.Error("expected IsFailOpen() = true for FailOpen outcome")
	}

	verified := NewVerifiedOutcome(nil, CertFingerprint{})
	if verified.IsFailOpen() {
		t.Error("expected IsFailOpen() = false for Verified outcome")
	}
}

func TestOutcome_IsNotATIAgent(t *testing.T) {
	notAgent := NewNotATIAgentOutcome("test.com")
	if !notAgent.IsNotATIAgent() {
		t.Error("expected IsNotATIAgent() = true")
	}

	verified := NewVerifiedOutcome(nil, CertFingerprint{})
	if verified.IsNotATIAgent() {
		t.Error("expected IsNotATIAgent() = false for Verified outcome")
	}
}

func TestOutcome_ToError(t *testing.T) {
	tests := []struct {
		name        string
		outcome     *VerificationOutcome
		wantNil     bool
		errContains string
	}{
		{
			name:    "verified returns nil",
			outcome: NewVerifiedOutcome(nil, CertFingerprint{}),
			wantNil: true,
		},
		{
			name:    "fail open returns nil",
			outcome: NewFailOpenOutcome(nil),
			wantNil: true,
		},
		{
			name: "not ANS agent with error",
			outcome: &VerificationOutcome{
				Type:  OutcomeNotATIAgent,
				Host:  "test.com",
				Error: errors.New("custom error"),
			},
			errContains: "custom error",
		},
		{
			name: "not ANS agent without error, with host",
			outcome: &VerificationOutcome{
				Type: OutcomeNotATIAgent,
				Host: "test.com",
			},
			errContains: "DNS record not found",
		},
		{
			name: "not ANS agent without error, without host",
			outcome: &VerificationOutcome{
				Type: OutcomeNotATIAgent,
			},
			errContains: "unknown",
		},
		{
			name:        "invalid status",
			outcome:     NewInvalidStatusOutcome(nil, models.TLStatusRevoked),
			errContains: "invalid badge status",
		},
		{
			name:        "fingerprint mismatch",
			outcome:     NewFingerprintMismatchOutcome(nil, "expected", "actual"),
			errContains: "fingerprint mismatch",
		},
		{
			name:        "hostname mismatch",
			outcome:     NewHostnameMismatchOutcome(nil, "expected", "actual"),
			errContains: "hostname mismatch",
		},
		{
			name:        "ATI name mismatch",
			outcome:     NewATINameMismatchOutcome(nil, "expected", "actual"),
			errContains: "ATI name mismatch",
		},
		{
			name: "DANE rejection",
			outcome: NewDANERejectionOutcome(nil, &DANEOutcome{
				Error: errors.New("DANE failed"),
			}),
			errContains: "DANE failed",
		},
		{
			name:        "DNS error",
			outcome:     NewDNSErrorOutcome(errors.New("dns error")),
			errContains: "dns error",
		},
		{
			name:        "tlog error",
			outcome:     NewTlogErrorOutcome(errors.New("tlog error")),
			errContains: "tlog error",
		},
		{
			name:        "cert error",
			outcome:     NewCertErrorOutcome(errors.New("cert error")),
			errContains: "cert error",
		},
		{
			name:        "URL validation error",
			outcome:     NewURLValidationErrorOutcome(errors.New("url error")),
			errContains: "url error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.outcome.ToError()
			if tt.wantNil {
				if err != nil {
					t.Errorf("ToError() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ToError() = nil, want error")
			}
			if tt.errContains != "" {
				if got := err.Error(); !containsStr(got, tt.errContains) {
					t.Errorf("ToError() = %q, want containing %q", got, tt.errContains)
				}
			}
		})
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestScittOutcomeConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		outcome   *VerificationOutcome
		wantType  OutcomeType
		wantTier  VerificationTier
		isSuccess bool
	}{
		{
			name:      "scitt error",
			outcome:   NewScittErrorOutcome(errors.New("scitt failed")),
			wantType:  OutcomeScittError,
			wantTier:  TierBadgeOnly,
			isSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.outcome.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", tt.outcome.Type, tt.wantType)
			}
			if tt.outcome.Tier != tt.wantTier {
				t.Errorf("Tier = %v, want %v", tt.outcome.Tier, tt.wantTier)
			}
			if tt.outcome.IsSuccess() != tt.isSuccess {
				t.Errorf("IsSuccess() = %v, want %v", tt.outcome.IsSuccess(), tt.isSuccess)
			}
		})
	}
}

func TestScittErrorToError(t *testing.T) {
	t.Parallel()

	err := errors.New("scitt verification failed")
	outcome := NewScittErrorOutcome(err)
	got := outcome.ToError()
	if !errors.Is(got, err) {
		t.Errorf("ToError() = %v, want %v", got, err)
	}
}

func TestVerificationTier_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tier VerificationTier
		want string
	}{
		{
			name: "badge only",
			tier: TierBadgeOnly,
			want: "BadgeOnly",
		},
		{
			name: "full scitt",
			tier: TierFullScitt,
			want: "FullScitt",
		},
		{
			name: "unknown tier",
			tier: VerificationTier(99),
			want: "VerificationTier(99)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.tier.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerificationTierDefaultsToZero(t *testing.T) {
	t.Parallel()

	// Existing constructors should default to TierBadgeOnly (zero value)
	outcome := NewVerifiedOutcome(nil, CertFingerprint{})
	if outcome.Tier != TierBadgeOnly {
		t.Errorf("default Tier = %v, want TierBadgeOnly", outcome.Tier)
	}
}
