package ati

import "fmt"

// VerificationPolicy defines the level of verification performed.
type VerificationPolicy int

const (
	PolicyNone          VerificationPolicy = iota // TLS handshake only
	PolicyPKIOnly                                 // CA chain + SAN matching
	PolicyBadgeRequired                           // PKI + badge verification (default)
	PolicyFull                                    // PKI + badge + DANE
)

// String returns a human-readable representation.
func (p VerificationPolicy) String() string {
	switch p {
	case PolicyNone:
		return "None"
	case PolicyPKIOnly:
		return "PKIOnly"
	case PolicyBadgeRequired:
		return "BadgeRequired"
	case PolicyFull:
		return "Full"
	default:
		return fmt.Sprintf("VerificationPolicy(%d)", int(p))
	}
}
