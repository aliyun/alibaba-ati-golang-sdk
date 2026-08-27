package verify

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// OfflineVerifier performs verification using pre-provisioned keys and embedded
// signed statements, without requiring TL connectivity per spec.
type OfflineVerifier struct {
	tlPublicKey  crypto.PublicKey
	tlKeyStore   *TLKeyStore
	producerKeys ProducerKeyLookup
}

// NewOfflineVerifier creates a verifier for offline/self-contained mode,
// pinned to a single TL seal public key (ECDSA or RSA).
func NewOfflineVerifier(tlPublicKey crypto.PublicKey, producerKeys ProducerKeyLookup) *OfflineVerifier {
	return &OfflineVerifier{
		tlPublicKey:  tlPublicKey,
		producerKeys: producerKeys,
	}
}

// NewOfflineVerifierWithKeyStore creates a verifier that looks up the TL seal
// key by seal.KeyID in store — use this to trust both the legacy ECDSA key
// and the newer RSA-3072 key at once, since the platform now signs seals
// with either depending on when the agent was registered.
func NewOfflineVerifierWithKeyStore(store *TLKeyStore, producerKeys ProducerKeyLookup) *OfflineVerifier {
	return &OfflineVerifier{
		tlKeyStore:   store,
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
	var sealErr error
	if v.tlKeyStore != nil {
		sealErr = VerifySealSignatureWithKeyStore(&tlResp, v.tlKeyStore)
	} else {
		sealErr = VerifySealSignature(&tlResp, v.tlPublicKey)
	}
	if sealErr != nil {
		return NewFailureResult(ansName, NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"offline: seal signature verification failed", WithCause(sealErr))), nil
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
