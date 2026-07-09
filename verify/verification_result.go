package verify

import "time"

// VerificationResult is the unified output from any verification operation per spec §11.3.
type VerificationResult struct {
	AnsName           string           `json:"ansName"`
	Connected         bool             `json:"connected"`
	TrustLevel        TrustLevel       `json:"trustLevel"`
	TrustIndex        int              `json:"trustIndex"`
	IdentityVerified  bool             `json:"identityVerified"`
	TLVerified        bool             `json:"tlVerified"`
	AgentCardVerified *AgentCardResult `json:"agentCardVerified,omitempty"`
	DNSSECStatus      string           `json:"dnssecStatus"`
	Status            string           `json:"status"`
	Warnings          []string         `json:"warnings,omitempty"`
	Error             *ANSError        `json:"error,omitempty"`
	Timestamp         time.Time        `json:"timestamp"`
}

// AgentCardResult holds the Agent Card verification details.
type AgentCardResult struct {
	SignatureValid  bool                    `json:"signatureValid"`
	CapHashValid   bool                    `json:"capHashValid"`
	SchemaValid    bool                    `json:"schemaValid"`
	ClaimsVerified []VerifiableClaimResult `json:"claimsVerified,omitempty"`
}

// VerifiableClaimResult holds the result of a single verifiable claim check.
type VerifiableClaimResult struct {
	ClaimType string `json:"claimType"`
	Issuer    string `json:"issuer"`
	Valid     bool   `json:"valid"`
	Error     string `json:"error,omitempty"`
}

// IsSuccess returns true if the verification connected successfully.
func (r *VerificationResult) IsSuccess() bool {
	return r.Connected && r.Error == nil
}

// ToError returns the ANSError if present, or nil.
func (r *VerificationResult) ToError() error {
	if r.Error != nil {
		return r.Error
	}
	return nil
}

// MeetsTrustLevel returns true if the result meets or exceeds the given trust level.
func (r *VerificationResult) MeetsTrustLevel(required TrustLevel) bool {
	return trustLevelOrd(r.TrustLevel) >= trustLevelOrd(required)
}

func trustLevelOrd(l TrustLevel) int {
	switch l {
	case TrustLevelHigh:
		return 3
	case TrustLevelVerified:
		return 2
	case TrustLevelBasic:
		return 1
	default:
		return 0
	}
}

// NewSuccessResult creates a successful verification result.
func NewSuccessResult(ansName string, trustIndex int, trustLevel TrustLevel) *VerificationResult {
	return &VerificationResult{
		AnsName:          ansName,
		Connected:        true,
		TrustLevel:       trustLevel,
		TrustIndex:       trustIndex,
		IdentityVerified: true,
		TLVerified:       true,
		Status:           "ACTIVE",
		Timestamp:        time.Now(),
	}
}

// NewFailureResult creates a failed verification result.
func NewFailureResult(ansName string, err *ANSError) *VerificationResult {
	return &VerificationResult{
		AnsName:    ansName,
		Connected:  false,
		TrustLevel: TrustLevelNone,
		Error:      err,
		Timestamp:  time.Now(),
	}
}
