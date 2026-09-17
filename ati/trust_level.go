package ati

// Deprecated: Use VerificationPolicy instead.
type TrustLevel = VerificationPolicy

// Deprecated: Use PolicyBasic instead.
const PKIOnly = PolicyBasic

// Deprecated: Use PolicyEnhanced instead.
const BadgeRequired = PolicyEnhanced

// Deprecated: Use PolicyAdvanced instead.
const DANEAndBadge = PolicyAdvanced

// Deprecated: use PolicyBasic, PolicyEnhanced, PolicyAdvanced instead.
const (
	TrustNone  = PolicyBasic
	TrustPKI   = PolicyBasic
	TrustBadge = PolicyEnhanced
	TrustFull  = PolicyAdvanced
	Bronze     = PolicyBasic
	Silver     = PolicyEnhanced
	Gold       = PolicyAdvanced
)
