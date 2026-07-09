package verify

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// OfflineVerifier performs verification using pre-provisioned keys and embedded
// signed statements, without requiring TL connectivity per spec.
type OfflineVerifier struct {
	tlPublicKey  *ecdsa.PublicKey
	producerKeys ProducerKeyLookup
}

// NewOfflineVerifier creates a verifier for offline/self-contained mode.
func NewOfflineVerifier(tlPublicKey *ecdsa.PublicKey, producerKeys ProducerKeyLookup) *OfflineVerifier {
	return &OfflineVerifier{
		tlPublicKey:  tlPublicKey,
		producerKeys: producerKeys,
	}
}

// VerifyOffline verifies a pre-packaged TL response without network access.
// The caller provides the raw TL response JSON (e.g., embedded in Agent Card).
func (v *OfflineVerifier) VerifyOffline(_ context.Context, tlResponseJSON []byte, cert *CertIdentity) (*VerificationResult, error) {
	if len(tlResponseJSON) == 0 {
		return nil, fmt.Errorf("offline: empty TL response")
	}

	var tlResp models.TLResponse
	if err := json.Unmarshal(tlResponseJSON, &tlResp); err != nil {
		return nil, fmt.Errorf("offline: failed to parse TL response: %w", err)
	}

	ansName := tlResp.Payload.AgentName

	// Step 1: Verify seal signature
	if err := VerifySealSignature(&tlResp, v.tlPublicKey); err != nil {
		return NewFailureResult(ansName, NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"offline: seal signature verification failed", WithCause(err))), nil
	}

	// Step 2: Verify inclusion proof
	if err := VerifyInclusionProof(&tlResp); err != nil {
		return NewFailureResult(ansName, NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"offline: inclusion proof verification failed", WithCause(err))), nil
	}

	// Step 3: Verify producer signature (optional)
	if v.producerKeys != nil {
		if err := VerifyProducerSignature(&tlResp, v.producerKeys); err != nil {
			return NewFailureResult(ansName, NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
				"offline: producer signature verification failed", WithCause(err))), nil
		}
	}

	// Step 4: Fingerprint match
	if !matchFingerprint(&tlResp, cert) {
		return NewFailureResult(ansName, NewANSError(CodeTLFingerprintMismatch, SeverityHard, StageTLVerify,
			"offline: certificate fingerprint does not match TL attestation")), nil
	}

	// Build result
	params := TrustIndexParams{
		IdentityVerified:  true,
		TLReceiptVerified: true,
		ProducerSigValid:  v.producerKeys != nil,
		MerkleProofValid:  true,
		FingerprintMatch:  true,
		StatusActive:      true,
	}
	trustIndex, trustLevel := ComputeTrustIndex(params)

	result := NewSuccessResult(ansName, trustIndex, trustLevel)
	result.TLVerified = true
	result.Timestamp = time.Now()
	result.Warnings = append(result.Warnings, "offline mode: revocation status unknown")

	return result, nil
}
