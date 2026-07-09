package verify

// TrustLevel represents the verification outcome trust tier per spec §11.3.
type TrustLevel string

const (
	TrustLevelNone     TrustLevel = "NONE"
	TrustLevelBasic    TrustLevel = "BASIC"
	TrustLevelVerified TrustLevel = "VERIFIED"
	TrustLevelHigh     TrustLevel = "HIGH"
)

// TrustIndexParams contains all verification signals used to compute the trust score.
type TrustIndexParams struct {
	IdentityVerified   bool
	DANEVerified       bool
	DNSSECValidated    bool
	TLReceiptVerified  bool
	ProducerSigValid   bool
	MerkleProofValid   bool
	FingerprintMatch   bool
	StatusActive       bool
	AgentCardVerified  bool
	CapHashValid       bool
	SchemaHashValid    bool
	ClaimsVerified     int
	ClaimsTotal        int
	CertExpiryWarning  bool
}

// Trust index weight constants.
const (
	weightIdentity    = 15
	weightDANE        = 10
	weightDNSSEC      = 5
	weightTLReceipt   = 15
	weightProducerSig = 10
	weightMerkle      = 10
	weightFingerprint = 10
	weightStatus      = 5
	weightAgentCard   = 5
	weightCapHash     = 5
	weightSchema      = 5
	weightClaims      = 5
)

// ComputeTrustIndex calculates the trust score (0-100) and level.
func ComputeTrustIndex(params TrustIndexParams) (int, TrustLevel) {
	score := 0

	if params.IdentityVerified {
		score += weightIdentity
	}
	if params.DANEVerified {
		score += weightDANE
	}
	if params.DNSSECValidated {
		score += weightDNSSEC
	}
	if params.TLReceiptVerified {
		score += weightTLReceipt
	}
	if params.ProducerSigValid {
		score += weightProducerSig
	}
	if params.MerkleProofValid {
		score += weightMerkle
	}
	if params.FingerprintMatch {
		score += weightFingerprint
	}
	if params.StatusActive {
		score += weightStatus
	}
	if params.AgentCardVerified {
		score += weightAgentCard
	}
	if params.CapHashValid {
		score += weightCapHash
	}
	if params.SchemaHashValid {
		score += weightSchema
	}
	if params.ClaimsTotal > 0 && params.ClaimsVerified > 0 {
		ratio := float64(params.ClaimsVerified) / float64(params.ClaimsTotal)
		score += int(float64(weightClaims) * ratio)
	}

	if params.CertExpiryWarning {
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score, trustLevelFromScore(score)
}

func trustLevelFromScore(score int) TrustLevel {
	switch {
	case score >= 80:
		return TrustLevelHigh
	case score >= 55:
		return TrustLevelVerified
	case score >= 30:
		return TrustLevelBasic
	default:
		return TrustLevelNone
	}
}
