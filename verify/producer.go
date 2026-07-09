package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// ProducerKeyLookup retrieves RA producer public keys by key ID.
type ProducerKeyLookup interface {
	GetProducerKey(kid string) (*ecdsa.PublicKey, error)
}

// VerifyProducerSignature verifies the RA producer signature over the
// canonicalized TLPayload. This is optional when EvidenceRef.SignatureRequired is false.
func VerifyProducerSignature(resp *models.TLResponse, keys ProducerKeyLookup) error {
	if resp == nil {
		return errors.New("producer: nil TL response")
	}

	if !resp.EvidenceRef.SignatureRequired {
		return nil
	}

	if keys == nil {
		return errors.New("producer: nil key lookup")
	}

	kid := resp.EvidenceRef.SubmitterID
	if kid == "" {
		return NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
			"evidence ref has no submitter ID")
	}

	pubKey, err := keys.GetProducerKey(kid)
	if err != nil {
		return NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
			fmt.Sprintf("producer key %q not found", kid), WithCause(err))
	}

	digest, err := computeProducerDigest(&resp.Payload)
	if err != nil {
		return NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
			"failed to compute producer digest", WithCause(err))
	}

	sigBytes, err := base64.StdEncoding.DecodeString(resp.EvidenceRef.EvidenceHash)
	if err != nil {
		return NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
			"failed to decode producer signature", WithCause(err))
	}

	if !ecdsa.VerifyASN1(pubKey, digest[:], sigBytes) {
		return NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
			"producer ECDSA signature verification failed")
	}

	return nil
}

// computeProducerDigest builds the JCS-canonicalized JSON of the TLPayload
// and returns its SHA-256 hash.
func computeProducerDigest(payload *models.TLPayload) ([32]byte, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, fmt.Errorf("producer: failed to marshal payload: %w", err)
	}

	canonical, err := JCSCanonicalize(payloadJSON)
	if err != nil {
		return [32]byte{}, fmt.Errorf("producer: JCS canonicalization failed: %w", err)
	}

	return sha256.Sum256(canonical), nil
}
