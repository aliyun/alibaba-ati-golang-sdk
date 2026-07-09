package verify

import "testing"

func TestVerificationResult_IsSuccess(t *testing.T) {
	tests := []struct {
		name   string
		result *VerificationResult
		want   bool
	}{
		{
			name:   "success result",
			result: NewSuccessResult("ati://test.com", 85, TrustLevelHigh),
			want:   true,
		},
		{
			name: "failure result",
			result: NewFailureResult("ati://test.com", NewANSError(
				CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify, "sig failed")),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerificationResult_MeetsTrustLevel(t *testing.T) {
	result := NewSuccessResult("ati://test.com", 70, TrustLevelVerified)

	if !result.MeetsTrustLevel(TrustLevelBasic) {
		t.Error("MeetsTrustLevel(BASIC) = false, want true for VERIFIED result")
	}
	if !result.MeetsTrustLevel(TrustLevelVerified) {
		t.Error("MeetsTrustLevel(VERIFIED) = false, want true for VERIFIED result")
	}
	if result.MeetsTrustLevel(TrustLevelHigh) {
		t.Error("MeetsTrustLevel(HIGH) = true, want false for VERIFIED result")
	}
}

func TestVerificationResult_ToError(t *testing.T) {
	success := NewSuccessResult("ati://test.com", 85, TrustLevelHigh)
	if err := success.ToError(); err != nil {
		t.Errorf("success.ToError() = %v, want nil", err)
	}

	failure := NewFailureResult("ati://test.com", NewANSError(
		CodeDNSCoreRecordMissing, SeverityHard, StageDNSDiscovery, "no record found"))
	if err := failure.ToError(); err == nil {
		t.Error("failure.ToError() = nil, want error")
	}
}

func TestNewSuccessResult(t *testing.T) {
	result := NewSuccessResult("ati://example.com", 92, TrustLevelHigh)

	if result.AnsName != "ati://example.com" {
		t.Errorf("AnsName = %q, want %q", result.AnsName, "ati://example.com")
	}
	if result.TrustIndex != 92 {
		t.Errorf("TrustIndex = %d, want 92", result.TrustIndex)
	}
	if result.TrustLevel != TrustLevelHigh {
		t.Errorf("TrustLevel = %v, want HIGH", result.TrustLevel)
	}
	if !result.Connected {
		t.Error("Connected = false, want true")
	}
}

func TestNewFailureResult(t *testing.T) {
	ansErr := NewANSError(CodeTLFingerprintMismatch, SeverityHard, StageTLVerify, "mismatch")
	result := NewFailureResult("ati://bad.com", ansErr)

	if result.AnsName != "ati://bad.com" {
		t.Errorf("AnsName = %q, want %q", result.AnsName, "ati://bad.com")
	}
	if result.Connected {
		t.Error("Connected = true, want false")
	}
	if result.Error == nil {
		t.Error("Error = nil, want ANSError")
	}
	if result.TrustLevel != TrustLevelNone {
		t.Errorf("TrustLevel = %v, want NONE", result.TrustLevel)
	}
}
