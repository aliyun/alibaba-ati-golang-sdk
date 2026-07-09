package verify

import (
	"testing"
	"time"
)

func TestDefaultTrustPolicy(t *testing.T) {
	tp := DefaultTrustPolicy()

	if tp.DNSSECMode != DNSSECModePrefer {
		t.Errorf("DNSSECMode = %v, want PREFER", tp.DNSSECMode)
	}
	if tp.TLUnreachable != FailureActionDegrade {
		t.Errorf("TLUnreachable = %v, want DEGRADE", tp.TLUnreachable)
	}
	if tp.CapHashMismatch != FailureActionDegrade {
		t.Errorf("CapHashMismatch = %v, want DEGRADE", tp.CapHashMismatch)
	}
	if tp.StaplingRequired {
		t.Error("StaplingRequired = true, want false")
	}
	if tp.MinTrustLevel != TrustLevelBasic {
		t.Errorf("MinTrustLevel = %v, want BASIC", tp.MinTrustLevel)
	}
	if tp.LongConnRecheckInterval != 5*time.Minute {
		t.Errorf("LongConnRecheckInterval = %v, want 5m", tp.LongConnRecheckInterval)
	}
}

func TestHighSecurityTrustPolicy(t *testing.T) {
	tp := HighSecurityTrustPolicy()

	if tp.DNSSECMode != DNSSECModeRequire {
		t.Errorf("DNSSECMode = %v, want REQUIRE", tp.DNSSECMode)
	}
	if tp.TLUnreachable != FailureActionFail {
		t.Errorf("TLUnreachable = %v, want FAIL", tp.TLUnreachable)
	}
	if tp.StaplingRequired != true {
		t.Error("StaplingRequired = false, want true")
	}
	if tp.MinTrustLevel != TrustLevelVerified {
		t.Errorf("MinTrustLevel = %v, want VERIFIED", tp.MinTrustLevel)
	}
}

func TestTrustPolicy_ShouldRejectDNSSECInsecure(t *testing.T) {
	require := &TrustPolicy{DNSSECMode: DNSSECModeRequire}
	prefer := &TrustPolicy{DNSSECMode: DNSSECModePrefer}

	if !require.ShouldRejectDNSSECInsecure() {
		t.Error("REQUIRE mode should reject DNSSEC insecure")
	}
	if prefer.ShouldRejectDNSSECInsecure() {
		t.Error("PREFER mode should not reject DNSSEC insecure")
	}
}

func TestTrustPolicy_ShouldRejectTLUnreachable(t *testing.T) {
	fail := &TrustPolicy{TLUnreachable: FailureActionFail}
	degrade := &TrustPolicy{TLUnreachable: FailureActionDegrade}

	if !fail.ShouldRejectTLUnreachable() {
		t.Error("FAIL action should reject TL unreachable")
	}
	if degrade.ShouldRejectTLUnreachable() {
		t.Error("DEGRADE action should not reject TL unreachable")
	}
}

func TestTrustPolicy_ShouldRejectCapHashMismatch(t *testing.T) {
	fail := &TrustPolicy{CapHashMismatch: FailureActionFail}
	degrade := &TrustPolicy{CapHashMismatch: FailureActionDegrade}

	if !fail.ShouldRejectCapHashMismatch() {
		t.Error("FAIL action should reject cap hash mismatch")
	}
	if degrade.ShouldRejectCapHashMismatch() {
		t.Error("DEGRADE action should not reject cap hash mismatch")
	}
}
