package verify

import "time"

// DNSSECMode controls DNSSEC requirement level.
type DNSSECMode string

const (
	DNSSECModeRequire DNSSECMode = "REQUIRE"
	DNSSECModePrefer  DNSSECMode = "PREFER"
)

// FailureAction defines what to do when a soft-fail condition occurs.
type FailureAction string

const (
	FailureActionFail    FailureAction = "FAIL"
	FailureActionDegrade FailureAction = "DEGRADE"
)

// TrustPolicy is the full configuration for verification behavior per spec §9.4.
type TrustPolicy struct {
	DNSSECMode              DNSSECMode    `json:"dnssecMode"`
	TLUnreachable           FailureAction `json:"tlUnreachable"`
	CapHashMismatch         FailureAction `json:"capHashMismatch"`
	StaplingRequired        bool          `json:"staplingRequired"`
	MinTrustLevel           TrustLevel    `json:"minTrustLevel"`
	OfflineMode             bool          `json:"offlineMode"`
	LongConnRecheckInterval time.Duration `json:"longConnRecheckInterval"`
}

// DefaultTrustPolicy returns the secure default trust policy.
func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{
		DNSSECMode:              DNSSECModePrefer,
		TLUnreachable:           FailureActionDegrade,
		CapHashMismatch:         FailureActionDegrade,
		StaplingRequired:        false,
		MinTrustLevel:           TrustLevelBasic,
		OfflineMode:             false,
		LongConnRecheckInterval: 5 * time.Minute,
	}
}

// HighSecurityTrustPolicy returns a strict policy for high-security scenarios.
func HighSecurityTrustPolicy() TrustPolicy {
	return TrustPolicy{
		DNSSECMode:              DNSSECModeRequire,
		TLUnreachable:           FailureActionFail,
		CapHashMismatch:         FailureActionFail,
		StaplingRequired:        true,
		MinTrustLevel:           TrustLevelVerified,
		OfflineMode:             false,
		LongConnRecheckInterval: 2 * time.Minute,
	}
}

// ShouldRejectDNSSECInsecure returns true if the policy demands rejection on insecure DNSSEC.
func (p *TrustPolicy) ShouldRejectDNSSECInsecure() bool {
	return p.DNSSECMode == DNSSECModeRequire
}

// ShouldRejectTLUnreachable returns true if the policy demands rejection on TL unavailability.
func (p *TrustPolicy) ShouldRejectTLUnreachable() bool {
	return p.TLUnreachable == FailureActionFail
}

// ShouldRejectCapHashMismatch returns true if the policy demands rejection on capabilities hash mismatch.
func (p *TrustPolicy) ShouldRejectCapHashMismatch() bool {
	return p.CapHashMismatch == FailureActionFail
}
