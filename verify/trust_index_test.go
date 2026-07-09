package verify

import "testing"

func TestComputeTrustIndex_FullTrust(t *testing.T) {
	params := TrustIndexParams{
		IdentityVerified:  true,
		TLReceiptVerified: true,
		ProducerSigValid:  true,
		MerkleProofValid:  true,
		FingerprintMatch:  true,
		DNSSECValidated:   true,
		DANEVerified:      true,
		AgentCardVerified: true,
		StatusActive:      true,
	}

	index, level := ComputeTrustIndex(params)
	if level != TrustLevelHigh {
		t.Errorf("ComputeTrustIndex() level = %v, want HIGH", level)
	}
	if index < 80 {
		t.Errorf("ComputeTrustIndex() index = %d, want >= 80", index)
	}
}

func TestComputeTrustIndex_MinimalTrust(t *testing.T) {
	params := TrustIndexParams{
		IdentityVerified: true,
	}

	index, level := ComputeTrustIndex(params)
	if level == TrustLevelHigh {
		t.Errorf("ComputeTrustIndex() level = HIGH with minimal params")
	}
	if index == 0 {
		t.Error("ComputeTrustIndex() index = 0 with IdentityVerified=true")
	}
}

func TestComputeTrustIndex_NoVerification(t *testing.T) {
	params := TrustIndexParams{}

	index, level := ComputeTrustIndex(params)
	if level != TrustLevelNone {
		t.Errorf("ComputeTrustIndex() level = %v, want NONE", level)
	}
	if index != 0 {
		t.Errorf("ComputeTrustIndex() index = %d, want 0", index)
	}
}

func TestComputeTrustIndex_VerifiedLevel(t *testing.T) {
	params := TrustIndexParams{
		IdentityVerified:  true,
		TLReceiptVerified: true,
		ProducerSigValid:  true,
		MerkleProofValid:  true,
		FingerprintMatch:  true,
		StatusActive:      true,
	}

	index, level := ComputeTrustIndex(params)
	if level != TrustLevelVerified && level != TrustLevelHigh {
		t.Errorf("ComputeTrustIndex() level = %v, want VERIFIED or HIGH", level)
	}
	if index < 55 {
		t.Errorf("ComputeTrustIndex() index = %d, want >= 55", index)
	}
}

func TestComputeTrustIndex_BasicLevel(t *testing.T) {
	params := TrustIndexParams{
		IdentityVerified:  true,
		TLReceiptVerified: true,
		StatusActive:      true,
	}

	index, level := ComputeTrustIndex(params)
	if index < 30 {
		t.Errorf("ComputeTrustIndex() index = %d, want >= 30 for BASIC", index)
	}
	_ = level
}

func TestTrustLevel_Values(t *testing.T) {
	if TrustLevelNone == TrustLevelBasic {
		t.Error("NONE should not equal BASIC")
	}
	if TrustLevelBasic == TrustLevelVerified {
		t.Error("BASIC should not equal VERIFIED")
	}
	if TrustLevelVerified == TrustLevelHigh {
		t.Error("VERIFIED should not equal HIGH")
	}
	if TrustLevelNone != "NONE" {
		t.Errorf("TrustLevelNone = %q, want NONE", TrustLevelNone)
	}
	if TrustLevelHigh != "HIGH" {
		t.Errorf("TrustLevelHigh = %q, want HIGH", TrustLevelHigh)
	}
}
