package ati

import "fmt"

// VerificationPolicy represents the verification policy level for agent communication.
type VerificationPolicy int

const (
	PolicyNone     VerificationPolicy = iota // L0: no verification (dev/test only)
	PolicyBasic                              // L1: PKI certificate validity only
	PolicyEnhanced                           // L2: PKI + Badge verification
	PolicyAdvanced                           // L3: PKI + Badge + DANE verification
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
	return p >= PolicyNone && p <= PolicyAdvanced
}

// ValidForServer reports whether the policy is valid for a server.
func (p VerificationPolicy) ValidForServer() bool {
	return p >= PolicyNone && p <= PolicyAdvanced
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
