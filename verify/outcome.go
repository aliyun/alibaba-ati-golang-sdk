package verify

import (
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// OutcomeType represents the type of verification outcome.
type OutcomeType int

const (
	// OutcomeVerified indicates verification passed.
	OutcomeVerified OutcomeType = iota
	// OutcomeNotATIAgent indicates no _ati-badge record found.
	OutcomeNotATIAgent
	// OutcomeInvalidStatus indicates badge status is invalid for connections.
	OutcomeInvalidStatus
	// OutcomeFingerprintMismatch indicates certificate fingerprint mismatch.
	OutcomeFingerprintMismatch
	// OutcomeHostnameMismatch indicates hostname mismatch.
	OutcomeHostnameMismatch
	// OutcomeATINameMismatch indicates ANS name mismatch.
	OutcomeATINameMismatch
	// OutcomeDNSError indicates DNS resolution failed.
	OutcomeDNSError
	// OutcomeTlogError indicates transparency log error.
	OutcomeTlogError
	// OutcomeCertError indicates certificate parsing error.
	OutcomeCertError
	// OutcomeFailOpen indicates verification was skipped due to fail-open policy.
	OutcomeFailOpen
	// OutcomeURLValidationError indicates the badge URL failed validation.
	OutcomeURLValidationError
	// OutcomeDANERejection indicates DANE/TLSA verification rejected the certificate.
	OutcomeDANERejection
	// OutcomeScittError indicates a SCITT verification error.
	OutcomeScittError
	// OutcomeGoldError indicates a Gold (CNNIC TL) verification error.
	OutcomeGoldError
)

// VerificationTier represents the level of SCITT verification achieved.
type VerificationTier int

const (
	// TierBadgeOnly indicates only badge-based verification was performed.
	TierBadgeOnly VerificationTier = iota
	// TierFullScitt indicates both receipt and status token were cryptographically verified.
	TierFullScitt
	// TierGold indicates CNNIC TL seal + Merkle proof were cryptographically verified.
	TierGold
)

// String returns a human-readable representation of the verification tier.
func (t VerificationTier) String() string {
	switch t {
	case TierBadgeOnly:
		return "BadgeOnly"
	case TierFullScitt:
		return "FullScitt"
	case TierGold:
		return "Gold"
	default:
		return fmt.Sprintf("VerificationTier(%d)", int(t))
	}
}

// VerificationOutcome represents the result of a verification operation.
type VerificationOutcome struct {
	// Type is the outcome type.
	Type OutcomeType
	// Tier indicates the SCITT verification level achieved (defaults to TierBadgeOnly).
	Tier VerificationTier
	// TLResponse is the TL response if verification partially completed (may be nil).
	TLResponse *models.TLResponse
	// MatchedFingerprint is the fingerprint that matched (for successful verification).
	MatchedFingerprint *CertFingerprint
	// Expected is the expected value for mismatch errors.
	Expected string
	// Actual is the actual value for mismatch errors.
	Actual string
	// Status is the agent status for invalid status errors.
	Status models.TLAgentStatus
	// Host is the hostname being verified (for error context).
	Host string
	// Error is the underlying error if any.
	Error error
	// Warnings contains non-fatal warnings (e.g., DEPRECATED badge status).
	Warnings []string
	// DANEOutcome contains the DANE/TLSA verification result (nil if DANE not configured).
	DANEOutcome *DANEOutcome
}

// NewVerifiedOutcome creates a successful verification outcome.
func NewVerifiedOutcome(tlResp *models.TLResponse, fingerprint CertFingerprint) *VerificationOutcome {
	return &VerificationOutcome{
		Type:               OutcomeVerified,
		TLResponse:         tlResp,
		MatchedFingerprint: &fingerprint,
	}
}

// NewNotATIAgentOutcome creates a not-ATI-agent outcome.
func NewNotATIAgentOutcome(host string) *VerificationOutcome {
	return &VerificationOutcome{
		Type: OutcomeNotATIAgent,
		Host: host,
	}
}

// NewInvalidStatusOutcome creates an invalid status outcome.
func NewInvalidStatusOutcome(tlResp *models.TLResponse, status models.TLAgentStatus) *VerificationOutcome {
	return &VerificationOutcome{
		Type:       OutcomeInvalidStatus,
		TLResponse: tlResp,
		Status:     status,
	}
}

// NewFingerprintMismatchOutcome creates a fingerprint mismatch outcome.
func NewFingerprintMismatchOutcome(tlResp *models.TLResponse, expected, actual string) *VerificationOutcome {
	return &VerificationOutcome{
		Type:       OutcomeFingerprintMismatch,
		TLResponse: tlResp,
		Expected:   expected,
		Actual:     actual,
	}
}

// NewHostnameMismatchOutcome creates a hostname mismatch outcome.
func NewHostnameMismatchOutcome(tlResp *models.TLResponse, expected, actual string) *VerificationOutcome {
	return &VerificationOutcome{
		Type:       OutcomeHostnameMismatch,
		TLResponse: tlResp,
		Expected:   expected,
		Actual:     actual,
	}
}

// NewATINameMismatchOutcome creates an ANS name mismatch outcome.
func NewATINameMismatchOutcome(tlResp *models.TLResponse, expected, actual string) *VerificationOutcome {
	return &VerificationOutcome{
		Type:       OutcomeATINameMismatch,
		TLResponse: tlResp,
		Expected:   expected,
		Actual:     actual,
	}
}

// NewDNSErrorOutcome creates a DNS error outcome.
func NewDNSErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeDNSError,
		Error: err,
	}
}

// NewTlogErrorOutcome creates a transparency log error outcome.
func NewTlogErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeTlogError,
		Error: err,
	}
}

// NewURLValidationErrorOutcome creates a URL validation error outcome.
func NewURLValidationErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeURLValidationError,
		Error: err,
	}
}

// NewFailOpenOutcome creates a fail-open outcome (verification skipped).
func NewFailOpenOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeFailOpen,
		Error: err,
	}
}

// NewDANERejectionOutcome creates a DANE rejection outcome.
func NewDANERejectionOutcome(tlResp *models.TLResponse, daneOutcome *DANEOutcome) *VerificationOutcome {
	return &VerificationOutcome{
		Type:        OutcomeDANERejection,
		TLResponse:  tlResp,
		Error:       daneOutcome.Error,
		DANEOutcome: daneOutcome,
	}
}

// NewCertErrorOutcome creates a certificate error outcome.
func NewCertErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeCertError,
		Error: err,
	}
}

// NewScittErrorOutcome creates a SCITT error outcome.
func NewScittErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeScittError,
		Error: err,
	}
}

// NewGoldErrorOutcome creates a Gold verification error outcome.
func NewGoldErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeGoldError,
		Error: err,
	}
}

// NewGoldVerifiedOutcome creates a successful Gold verification outcome.
func NewGoldVerifiedOutcome(fingerprint CertFingerprint) *VerificationOutcome {
	return &VerificationOutcome{
		Type:               OutcomeVerified,
		Tier:               TierGold,
		MatchedFingerprint: &fingerprint,
	}
}

// IsSuccess returns true if verification was successful or fail-open was applied.
func (o *VerificationOutcome) IsSuccess() bool {
	return o.Type == OutcomeVerified || o.Type == OutcomeFailOpen
}

// IsFailOpen returns true if verification was skipped due to fail-open policy.
func (o *VerificationOutcome) IsFailOpen() bool {
	return o.Type == OutcomeFailOpen
}

// IsNotATIAgent returns true if the agent is not registered with ATI.
func (o *VerificationOutcome) IsNotATIAgent() bool {
	return o.Type == OutcomeNotATIAgent
}

// ToError converts the outcome to an error if verification failed.
func (o *VerificationOutcome) ToError() error {
	switch o.Type {
	case OutcomeVerified, OutcomeFailOpen:
		return nil
	case OutcomeNotATIAgent:
		// If an underlying error exists, return it directly for better context
		if o.Error != nil {
			return o.Error
		}
		host := o.Host
		if host == "" {
			host = "unknown"
		}
		return &DNSError{Type: DNSErrorNotFound, Fqdn: host}
	case OutcomeInvalidStatus:
		return &VerificationError{
			Type:   VerificationErrorInvalidStatus,
			Actual: string(o.Status),
		}
	case OutcomeFingerprintMismatch:
		return &VerificationError{
			Type:     VerificationErrorFingerprintMismatch,
			Expected: o.Expected,
			Actual:   o.Actual,
		}
	case OutcomeHostnameMismatch:
		return &VerificationError{
			Type:     VerificationErrorHostnameMismatch,
			Expected: o.Expected,
			Actual:   o.Actual,
		}
	case OutcomeATINameMismatch:
		return &VerificationError{
			Type:     VerificationErrorATINameMismatch,
			Expected: o.Expected,
			Actual:   o.Actual,
		}
	case OutcomeDANERejection:
		return o.Error
	case OutcomeDNSError, OutcomeTlogError, OutcomeCertError, OutcomeURLValidationError, OutcomeScittError, OutcomeGoldError:
		return o.Error
	default:
		return o.Error
	}
}
