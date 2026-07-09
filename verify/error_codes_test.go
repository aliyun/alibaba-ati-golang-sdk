package verify

import (
	"errors"
	"testing"
)

func TestNewANSError(t *testing.T) {
	err := NewANSError(CodeDNSCoreRecordMissing, SeverityHard, StageDNSDiscovery, "no _ati record found")

	if err.Code != CodeDNSCoreRecordMissing {
		t.Errorf("Code = %q, want %q", err.Code, CodeDNSCoreRecordMissing)
	}
	if err.Severity != SeverityHard {
		t.Errorf("Severity = %v, want HARD", err.Severity)
	}
	if err.Stage != StageDNSDiscovery {
		t.Errorf("Stage = %v, want %v", err.Stage, StageDNSDiscovery)
	}
	if err.Message != "no _ati record found" {
		t.Errorf("Message = %q", err.Message)
	}
}

func TestANSError_Error(t *testing.T) {
	err := NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify, "signature invalid")
	msg := err.Error()

	if msg == "" {
		t.Error("Error() returned empty string")
	}
	// Should contain the error code
	if !contains(msg, string(CodeTLReceiptSigInvalid)) {
		t.Errorf("Error() = %q, should contain error code %q", msg, CodeTLReceiptSigInvalid)
	}
}

func TestANSError_WithCause(t *testing.T) {
	cause := errors.New("connection refused")
	err := NewANSError(CodeTLUnreachable, SeveritySoft, StageTLVerify, "TL unreachable", WithCause(cause))

	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
	// Unwrap should return the cause
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
}

func TestANSError_WithEvidence(t *testing.T) {
	err := NewANSError(CodeDNSSECBogus, SeverityHard, StageDNSDiscovery, "chain broken",
		WithEvidence("RRSIG expired at 2024-01-01T00:00:00Z"))

	if err.AnchorEvidence != "RRSIG expired at 2024-01-01T00:00:00Z" {
		t.Errorf("AnchorEvidence = %q", err.AnchorEvidence)
	}
}

func TestANSError_IsHard(t *testing.T) {
	hard := NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify, "hard fail")
	soft := NewANSError(CodeTLUnreachable, SeveritySoft, StageTLVerify, "soft fail")

	if !hard.IsHard() {
		t.Error("hard error.IsHard() = false")
	}
	if soft.IsHard() {
		t.Error("soft error.IsHard() = true")
	}
}

