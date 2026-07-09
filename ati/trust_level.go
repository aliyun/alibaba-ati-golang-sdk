package ati

import "fmt"

// TrustLevel represents the verification trust level for agent communication.
type TrustLevel int

const (
	// PKIOnly performs only PKI certificate validity checks (no ATI badge or DANE).
	PKIOnly TrustLevel = iota
	// BadgeRequired requires badge verification (DNS _ati-badge → TLog → fingerprint match).
	BadgeRequired
	// DANEAndBadge requires both badge verification and DANE/TLSA verification.
	DANEAndBadge
)

// Deprecated: use PKIOnly, BadgeRequired, DANEAndBadge instead.
const (
	TrustNone  = PKIOnly
	TrustPKI   = PKIOnly
	TrustBadge = BadgeRequired
	TrustFull  = DANEAndBadge
	Bronze     = PKIOnly
	Silver     = BadgeRequired
	Gold       = DANEAndBadge
)

// ValidForClient reports whether the level is supported for a client.
func (l TrustLevel) ValidForClient() bool {
	return l >= PKIOnly && l <= DANEAndBadge
}

// ValidForServer reports whether the level is supported for a server.
func (l TrustLevel) ValidForServer() bool {
	return l >= PKIOnly && l <= DANEAndBadge
}

func (l TrustLevel) String() string {
	switch l {
	case PKIOnly:
		return "PKI_ONLY"
	case BadgeRequired:
		return "BADGE_REQUIRED"
	case DANEAndBadge:
		return "DANE_AND_BADGE"
	default:
		return fmt.Sprintf("TrustLevel(%d)", int(l))
	}
}
