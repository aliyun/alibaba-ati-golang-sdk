package ati

import "fmt"

// VerificationPolicy defines the level of verification performed.
type VerificationPolicy int

const (
	PolicyPKI          VerificationPolicy = iota // CA chain verification (PKI only)
	PolicyPKIBadge                               // CA chain + badge transparency log verification (default)
	PolicyPKIBadgeDANE                           // CA chain + badge + DANE TLSA verification
)

// String returns a human-readable representation.
func (p VerificationPolicy) String() string {
	switch p {
	case PolicyPKI:
		return "PKI"
	case PolicyPKIBadge:
		return "PKIBadge"
	case PolicyPKIBadgeDANE:
		return "PKIBadgeDANE"
	default:
		return fmt.Sprintf("VerificationPolicy(%d)", int(p))
	}
}
