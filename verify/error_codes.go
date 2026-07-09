package verify

import "fmt"

// Severity indicates whether an error is a hard rejection or soft warning.
type Severity string

const (
	SeverityHard Severity = "HARD"
	SeveritySoft Severity = "SOFT"
)

// Stage indicates the verification pipeline stage where the error occurred.
type Stage int

const (
	StageDNSDiscovery Stage = 1
	StageMTLS         Stage = 2
	StageTLVerify     Stage = 3
	StageAgentCard    Stage = 4
	StageSession      Stage = 5
)

// Error code constants per spec §9.2.
const (
	CodeDNSCoreRecordMissing    = "ANS-1001"
	CodeDNSSECBogus             = "ANS-1002"
	CodeDNSSECInsecure          = "ANS-1003"
	CodeCertChainInvalid        = "ANS-2001"
	CodeCertExpired             = "ANS-2002"
	CodeDANEFingerprintMismatch = "ANS-2003"
	CodeSANURIMismatch          = "ANS-2004"
	CodeSANURIMissing           = "ANS-2005"
	CodeTLReceiptSigInvalid     = "ANS-3001"
	CodeTLInclusionProofFailed  = "ANS-3002"
	CodeProducerSigInvalid      = "ANS-3003"
	CodeTLFingerprintMismatch   = "ANS-3004"
	CodeStatusRevoked           = "ANS-3005"
	CodeStatusExpired           = "ANS-3006"
	CodeStatusWarning           = "ANS-3007"
	CodeTLUnreachable           = "ANS-3008"
	CodeAgentCardFetchFailed    = "ANS-4001"
	CodeCapHashMismatch         = "ANS-4002"
	CodeAgentCardSigInvalid     = "ANS-4003"
	CodeSchemaHashMismatch      = "ANS-4004"
	CodeVerifiableClaimInvalid  = "ANS-4005"
	CodeRevokedDuringSession    = "ANS-5001"
	CodeStaplingExpired         = "ANS-5002"
)

// ANSError is the unified structured error type for all verification failures.
type ANSError struct {
	Code           string   `json:"code"`
	Severity       Severity `json:"severity"`
	Stage          Stage    `json:"stage"`
	Message        string   `json:"message"`
	AnchorEvidence any      `json:"anchorEvidence,omitempty"`
	Cause          error    `json:"-"`
}

func (e *ANSError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *ANSError) Unwrap() error { return e.Cause }

// IsHard returns true if this error demands connection rejection.
func (e *ANSError) IsHard() bool { return e.Severity == SeverityHard }

// ANSErrorOption configures an ANSError.
type ANSErrorOption func(*ANSError)

// WithEvidence attaches anchor evidence to an error.
func WithEvidence(evidence any) ANSErrorOption {
	return func(e *ANSError) { e.AnchorEvidence = evidence }
}

// WithCause attaches a wrapped cause to an error.
func WithCause(cause error) ANSErrorOption {
	return func(e *ANSError) { e.Cause = cause }
}

// NewANSError creates a structured ANS verification error.
func NewANSError(code string, severity Severity, stage Stage, msg string, opts ...ANSErrorOption) *ANSError {
	e := &ANSError{
		Code:     code,
		Severity: severity,
		Stage:    stage,
		Message:  msg,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}
