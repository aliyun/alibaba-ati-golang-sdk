package verify

import (
	"errors"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// TestVerificationTier_String_Gold exercises the TierGold String() method at
// outcome.go:63, confirming it returns "Gold".
func TestVerificationTier_String_Gold(t *testing.T) {
	t.Parallel()

	if got := TierGold.String(); got != "Gold" {
		t.Errorf("TierGold.String() = %q, want %q", got, "Gold")
	}
}

// TestNewGoldErrorOutcome exercises the NewGoldErrorOutcome constructor at
// outcome.go:210-214, confirming it sets Type to OutcomeGoldError and stores
// the underlying error.
func TestNewGoldErrorOutcome(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("gold verification failed")
	outcome := NewGoldErrorOutcome(underlyingErr)

	if outcome.Type != OutcomeGoldError {
		t.Errorf("Type = %v, want OutcomeGoldError", outcome.Type)
	}
	if outcome.Tier != TierBadgeOnly {
		t.Errorf("Tier = %v, want TierBadgeOnly (default)", outcome.Tier)
	}
	if !errors.Is(outcome.Error, underlyingErr) {
		t.Errorf("Error = %v, want %v", outcome.Error, underlyingErr)
	}
	if outcome.IsSuccess() {
		t.Error("expected IsSuccess() = false for gold error outcome")
	}
	if outcome.IsFailOpen() {
		t.Error("expected IsFailOpen() = false for gold error outcome")
	}
	if outcome.IsNotATIAgent() {
		t.Error("expected IsNotATIAgent() = false for gold error outcome")
	}
}

// TestNewGoldErrorOutcome_NilError exercises NewGoldErrorOutcome with a nil
// error, confirming the outcome is still created with the correct type.
func TestNewGoldErrorOutcome_NilError(t *testing.T) {
	t.Parallel()

	outcome := NewGoldErrorOutcome(nil)

	if outcome.Type != OutcomeGoldError {
		t.Errorf("Type = %v, want OutcomeGoldError", outcome.Type)
	}
	if outcome.Error != nil {
		t.Errorf("Error = %v, want nil", outcome.Error)
	}
}

// TestNewGoldVerifiedOutcome exercises the NewGoldVerifiedOutcome constructor at
// outcome.go:218-223, confirming it sets Type to OutcomeVerified and Tier to
// TierGold, and stores the fingerprint.
func TestNewGoldVerifiedOutcome(t *testing.T) {
	t.Parallel()

	fp := CertFingerprintFromBytes([32]byte{0xAA, 0xBB, 0xCC})
	outcome := NewGoldVerifiedOutcome(fp)

	if outcome.Type != OutcomeVerified {
		t.Errorf("Type = %v, want OutcomeVerified", outcome.Type)
	}
	if outcome.Tier != TierGold {
		t.Errorf("Tier = %v, want TierGold", outcome.Tier)
	}
	if outcome.MatchedFingerprint == nil {
		t.Fatal("expected non-nil MatchedFingerprint")
	}
	if !outcome.MatchedFingerprint.Equal(fp) {
		t.Errorf("MatchedFingerprint = %v, want %v", outcome.MatchedFingerprint, fp)
	}
	if !outcome.IsSuccess() {
		t.Error("expected IsSuccess() = true for gold verified outcome")
	}
	if outcome.IsFailOpen() {
		t.Error("expected IsFailOpen() = false for gold verified outcome")
	}
	if outcome.IsNotATIAgent() {
		t.Error("expected IsNotATIAgent() = false for gold verified outcome")
	}
}

// TestNewGoldVerifiedOutcome_ToError exercises that the gold verified outcome
// returns nil from ToError (success path).
func TestNewGoldVerifiedOutcome_ToError(t *testing.T) {
	t.Parallel()

	fp := CertFingerprintFromBytes([32]byte{0x01})
	outcome := NewGoldVerifiedOutcome(fp)

	if err := outcome.ToError(); err != nil {
		t.Errorf("ToError() = %v, want nil", err)
	}
}

// TestNewGoldErrorOutcome_ToError exercises that the gold error outcome returns
// the underlying error from ToError (the OutcomeGoldError branch at
// outcome.go:281-282 which falls through to line 284: return o.Error).
func TestNewGoldErrorOutcome_ToError(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("gold seal verification failed")
	outcome := NewGoldErrorOutcome(underlyingErr)

	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error from ToError()")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestNewGoldErrorOutcome_ToError_NilError exercises the gold error outcome
// ToError path with a nil underlying error (returns nil from line 284).
func TestNewGoldErrorOutcome_ToError_NilError(t *testing.T) {
	t.Parallel()

	outcome := NewGoldErrorOutcome(nil)

	err := outcome.ToError()
	if err != nil {
		t.Errorf("ToError() = %v, want nil", err)
	}
}

// TestToError_UnknownOutcomeType exercises the default case in ToError at
// outcome.go:283-284, which returns o.Error for unrecognized outcome types.
func TestToError_UnknownOutcomeType(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("unknown outcome error")
	outcome := &VerificationOutcome{
		Type:  OutcomeType(999), // unrecognized type
		Error: underlyingErr,
	}

	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error from ToError() for unknown type")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestToError_UnknownOutcomeType_NilError exercises the default case in
// ToError at outcome.go:283-284 with a nil underlying error.
func TestToError_UnknownOutcomeType_NilError(t *testing.T) {
	t.Parallel()

	outcome := &VerificationOutcome{
		Type: OutcomeType(999), // unrecognized type
	}

	err := outcome.ToError()
	if err != nil {
		t.Errorf("ToError() = %v, want nil", err)
	}
}

// TestToError_SCittErrorExercisesOutcomeScittError confirms the ScittError
// branch in ToError returns o.Error. This covers the branch at outcome.go:281
// (OutcomeScittError in the case list) and line 282 (return o.Error).
func TestToError_ScittError(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("scitt verification failed")
	outcome := NewScittErrorOutcome(underlyingErr)

	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error from ToError()")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestToError_GoldErrorBranchExplicitly exercises the OutcomeGoldError case
// explicitly listed in the switch at outcome.go:281, confirming it falls
// through to return o.Error at line 282.
func TestToError_GoldErrorBranchExplicitly(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("explicit gold error")
	outcome := &VerificationOutcome{
		Type:  OutcomeGoldError,
		Error: underlyingErr,
	}

	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestNewURLValidationErrorOutcome_ToError exercises the URLValidationError
// branch in ToError, confirming it returns the underlying error. This is
// listed in the case at outcome.go:281.
func TestNewURLValidationErrorOutcome_ToError(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("url validation failed")
	outcome := NewURLValidationErrorOutcome(underlyingErr)

	if outcome.Type != OutcomeURLValidationError {
		t.Errorf("Type = %v, want OutcomeURLValidationError", outcome.Type)
	}
	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestNewCertErrorOutcome_ToError exercises the CertError branch in ToError.
func TestNewCertErrorOutcome_ToError(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("cert parsing failed")
	outcome := NewCertErrorOutcome(underlyingErr)

	if outcome.Type != OutcomeCertError {
		t.Errorf("Type = %v, want OutcomeCertError", outcome.Type)
	}
	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestNewDNSErrorOutcome_ToError exercises the DNSError branch in ToError.
func TestNewDNSErrorOutcome_ToError(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("dns lookup failed")
	outcome := NewDNSErrorOutcome(underlyingErr)

	if outcome.Type != OutcomeDNSError {
		t.Errorf("Type = %v, want OutcomeDNSError", outcome.Type)
	}
	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestNewTlogErrorOutcome_ToError exercises the TlogError branch in ToError.
func TestNewTlogErrorOutcome_ToError(t *testing.T) {
	t.Parallel()

	underlyingErr := errors.New("tlog lookup failed")
	outcome := NewTlogErrorOutcome(underlyingErr)

	if outcome.Type != OutcomeTlogError {
		t.Errorf("Type = %v, want OutcomeTlogError", outcome.Type)
	}
	err := outcome.ToError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, underlyingErr) {
		t.Errorf("ToError() = %v, want %v", err, underlyingErr)
	}
}

// TestGoldOutcomeConstructors comprehensively tests the Gold-related outcome
// constructors and their interactions with IsSuccess, IsFailOpen, and
// IsNotATIAgent.
func TestGoldOutcomeConstructors(t *testing.T) {
	t.Parallel()

	fp := CertFingerprintFromBytes([32]byte{0x42})

	tests := []struct {
		name      string
		outcome   *VerificationOutcome
		wantType  OutcomeType
		wantTier  VerificationTier
		isSuccess bool
	}{
		{
			name:      "gold verified",
			outcome:   NewGoldVerifiedOutcome(fp),
			wantType:  OutcomeVerified,
			wantTier:  TierGold,
			isSuccess: true,
		},
		{
			name:      "gold error",
			outcome:   NewGoldErrorOutcome(errors.New("gold failed")),
			wantType:  OutcomeGoldError,
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

// TestOutcomeType_Constants verifies that the outcome type constants have
// distinct values, ensuring the switch cases in ToError are distinguishable.
func TestOutcomeType_Constants(t *testing.T) {
	t.Parallel()

	// Ensure OutcomeGoldError is distinct from other types used in the
	// ToError switch statement.
	if OutcomeGoldError == OutcomeScittError {
		t.Error("OutcomeGoldError should be distinct from OutcomeScittError")
	}
	if OutcomeGoldError == OutcomeCertError {
		t.Error("OutcomeGoldError should be distinct from OutcomeCertError")
	}
	if OutcomeGoldError == OutcomeDNSError {
		t.Error("OutcomeGoldError should be distinct from OutcomeDNSError")
	}
	if OutcomeGoldError == OutcomeTlogError {
		t.Error("OutcomeGoldError should be distinct from OutcomeTlogError")
	}
	if OutcomeGoldError == OutcomeURLValidationError {
		t.Error("OutcomeGoldError should be distinct from OutcomeURLValidationError")
	}
}

// TestToError_AllBranchesCoverage is a comprehensive table-driven test that
// exercises every branch in the ToError switch statement, including the
// default case.
func TestToError_AllBranchesCoverage(t *testing.T) {
	t.Parallel()

	tlResp := &models.TLResponse{}
	customErr := errors.New("underlying")

	tests := []struct {
		name    string
		outcome *VerificationOutcome
		wantNil bool
	}{
		{name: "verified", outcome: NewVerifiedOutcome(tlResp, CertFingerprint{}), wantNil: true},
		{name: "fail open", outcome: NewFailOpenOutcome(nil), wantNil: true},
		{name: "not ATI agent with error", outcome: &VerificationOutcome{Type: OutcomeNotATIAgent, Host: "h", Error: customErr}},
		{name: "not ATI agent without error", outcome: &VerificationOutcome{Type: OutcomeNotATIAgent, Host: "h"}},
		{name: "not ATI agent no host", outcome: &VerificationOutcome{Type: OutcomeNotATIAgent}},
		{name: "invalid status", outcome: NewInvalidStatusOutcome(tlResp, models.TLStatusRevoked)},
		{name: "fingerprint mismatch", outcome: NewFingerprintMismatchOutcome(tlResp, "a", "b")},
		{name: "hostname mismatch", outcome: NewHostnameMismatchOutcome(tlResp, "a", "b")},
		{name: "ATI name mismatch", outcome: NewATINameMismatchOutcome(tlResp, "a", "b")},
		{name: "DANE rejection", outcome: NewDANERejectionOutcome(tlResp, &DANEOutcome{Error: customErr})},
		{name: "DNS error", outcome: NewDNSErrorOutcome(customErr)},
		{name: "tlog error", outcome: NewTlogErrorOutcome(customErr)},
		{name: "cert error", outcome: NewCertErrorOutcome(customErr)},
		{name: "URL validation error", outcome: NewURLValidationErrorOutcome(customErr)},
		{name: "scitt error", outcome: NewScittErrorOutcome(customErr)},
		{name: "gold error", outcome: NewGoldErrorOutcome(customErr)},
		{name: "gold verified", outcome: NewGoldVerifiedOutcome(CertFingerprint{}), wantNil: true},
		{name: "unknown type with error", outcome: &VerificationOutcome{Type: OutcomeType(999), Error: customErr}},
		{name: "unknown type no error", outcome: &VerificationOutcome{Type: OutcomeType(999)}, wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.outcome.ToError()
			if tt.wantNil {
				if err != nil {
					t.Errorf("ToError() = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Error("ToError() = nil, want error")
				}
			}
		})
	}
}
