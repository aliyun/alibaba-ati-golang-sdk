package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// StapledCredential represents a short-lived status credential per spec §8.4.
// The agent presents this during handshake to prove current validity without
// requiring the verifier to query the TL in real time.
type StapledCredential struct {
	AnsID     string    `json:"ansId"`
	Status    string    `json:"status"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Signature string    `json:"signature"`
	Kid       string    `json:"kid"`
}

// ParseStapledCredential parses a stapled credential from JSON bytes.
func ParseStapledCredential(raw []byte) (*StapledCredential, error) {
	var cred StapledCredential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("stapling: failed to parse credential: %w", err)
	}
	if cred.AnsID == "" {
		return nil, fmt.Errorf("stapling: missing ansId")
	}
	if cred.Status == "" {
		return nil, fmt.Errorf("stapling: missing status")
	}
	if cred.Signature == "" {
		return nil, fmt.Errorf("stapling: missing signature")
	}
	return &cred, nil
}

// VerifyStapledCredential verifies a stapled credential's signature and freshness.
// Returns nil if valid, or an ANSError if expired/invalid.
func VerifyStapledCredential(cred *StapledCredential, keys ProducerKeyLookup, now time.Time) error {
	if cred == nil {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			"no stapled credential provided")
	}

	// Check freshness
	if now.After(cred.ExpiresAt) {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			fmt.Sprintf("stapled credential expired at %s", cred.ExpiresAt.Format(time.RFC3339)))
	}
	if now.Before(cred.IssuedAt) {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			"stapled credential issuedAt is in the future")
	}

	// Check status
	if cred.Status == "REVOKED" || cred.Status == "EXPIRED" {
		return NewANSError(CodeStatusRevoked, SeverityHard, StageSession,
			fmt.Sprintf("stapled credential indicates status: %s", cred.Status))
	}

	// Verify signature
	if keys == nil {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			"no key lookup configured for stapling verification")
	}

	pubKey, err := keys.GetProducerKey(cred.Kid)
	if err != nil {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			fmt.Sprintf("stapling key %q not found", cred.Kid), WithCause(err))
	}

	digest, err := computeStaplingDigest(cred)
	if err != nil {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			"failed to compute stapling digest", WithCause(err))
	}

	sigBytes, err := base64.StdEncoding.DecodeString(cred.Signature)
	if err != nil {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			"failed to decode stapling signature", WithCause(err))
	}

	if !ecdsa.VerifyASN1(pubKey, digest[:], sigBytes) {
		return NewANSError(CodeStaplingExpired, SeveritySoft, StageSession,
			"stapling signature verification failed")
	}

	return nil
}

// computeStaplingDigest builds SHA-256(JCS({ansId, status, issuedAt, expiresAt})).
func computeStaplingDigest(cred *StapledCredential) ([32]byte, error) {
	payload := struct {
		AnsID     string `json:"ansId"`
		Status    string `json:"status"`
		IssuedAt  string `json:"issuedAt"`
		ExpiresAt string `json:"expiresAt"`
	}{
		AnsID:     cred.AnsID,
		Status:    cred.Status,
		IssuedAt:  cred.IssuedAt.Format(time.RFC3339),
		ExpiresAt: cred.ExpiresAt.Format(time.RFC3339),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, err
	}

	canonical, err := JCSCanonicalize(payloadJSON)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(canonical), nil
}
