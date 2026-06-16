package verify

import "crypto/x509"

// TrustPolicy defines trust evaluation rules per spec §9.4.
type TrustPolicy struct {
	TrustedIssuers []string
	MinKeyStrength int
}

// ProducerKeyLookup resolves producer signing keys by key ID.
type ProducerKeyLookup interface {
	LookupKey(keyID string) (interface{}, error)
}

// AgentCardVerifier verifies Agent Card claims.
type AgentCardVerifier struct {
	TrustedIssuers []string
}

// SessionMonitor monitors long-lived TLS sessions for revocation events.
type SessionMonitor struct {
	PollInterval int
}

// OCSPChecker performs OCSP revocation checks on certificates.
type OCSPChecker struct {
	Responders []*x509.Certificate
}
