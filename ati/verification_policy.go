package ati

import "fmt"

// VerificationPolicy represents the verification policy level for agent communication.
type VerificationPolicy int

const (
	// PolicyBasic is the zero-value default (fail-safe). Preserves backward
	// compatibility with the old PKIOnly=0 enum so that any persisted integer
	// 0 still means "PKI verification", not "no verification".
	PolicyBasic    VerificationPolicy = 0  // L1: PKI certificate validity only
	PolicyEnhanced VerificationPolicy = 1  // L2: PKI + Badge verification
	PolicyAdvanced VerificationPolicy = 2  // L3: PKI + Badge + DANE verification
	PolicyNone     VerificationPolicy = -1 // L0: no verification (dev/test only, explicit opt-in required)
)

// DisplayName returns the console display label for the policy.
func (p VerificationPolicy) DisplayName() string {
	switch p {
	case PolicyNone:
		return "L0 None"
	case PolicyBasic:
		return "L1 Basic"
	case PolicyEnhanced:
		return "L2 Enhanced"
	case PolicyAdvanced:
		return "L3 Advanced"
	default:
		return fmt.Sprintf("Unknown(%d)", int(p))
	}
}

// HasBadgeVerification reports whether this policy includes badge verification.
func (p VerificationPolicy) HasBadgeVerification() bool {
	return p >= PolicyEnhanced
}

// HasDANEVerification reports whether this policy includes DANE/TLSA verification.
func (p VerificationPolicy) HasDANEVerification() bool {
	return p >= PolicyAdvanced
}

// ValidForClient reports whether the policy is valid for a client.
func (p VerificationPolicy) ValidForClient() bool {
	return p == PolicyNone || (p >= PolicyBasic && p <= PolicyAdvanced)
}

// ValidForServer reports whether the policy is valid for a server.
func (p VerificationPolicy) ValidForServer() bool {
	return p == PolicyNone || (p >= PolicyBasic && p <= PolicyAdvanced)
}

func (p VerificationPolicy) String() string {
	switch p {
	case PolicyNone:
		return "NONE"
	case PolicyBasic:
		return "BASIC"
	case PolicyEnhanced:
		return "ENHANCED"
	case PolicyAdvanced:
		return "ADVANCED"
	default:
		return fmt.Sprintf("VerificationPolicy(%d)", int(p))
	}
}
