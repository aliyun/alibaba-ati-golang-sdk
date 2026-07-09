package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// VerifySealSignature verifies the CNNIC TL seal signature over the four sealed fields:
// JCS({status, schemaVersion, payload, evidenceRef}) -> SHA-256 -> ECDSA P-256.
// When trustedKey is nil, the embedded public key from resp.Seal.PublicKey is used.
func VerifySealSignature(resp *models.TLResponse, trustedKey *ecdsa.PublicKey) error {
	if resp == nil {
		return errors.New("seal: nil TL response")
	}

	seal := &resp.Seal
	if seal.Signature == "" {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"seal has empty signature")
	}
	if seal.KeyID == "" {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"seal has no key ID")
	}

	key := trustedKey
	if key == nil {
		if seal.PublicKey == "" {
			return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
				"no trusted TL public key and no embedded public key in seal")
		}
		parsed, err := ParseECDSAPublicKeyPEM(seal.PublicKey)
		if err != nil {
			return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
				"failed to parse embedded seal public key", WithCause(err))
		}
		key = parsed
	}

	digest, err := computeSealDigest(resp)
	if err != nil {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"failed to compute seal digest", WithCause(err))
	}

	sigBytes, err := base64.StdEncoding.DecodeString(seal.Signature)
	if err != nil {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"failed to decode seal signature", WithCause(err))
	}

	if !ecdsa.VerifyASN1(key, digest[:], sigBytes) {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"seal ECDSA signature verification failed")
	}

	return nil
}

// computeSealDigest builds the JCS-canonical representation of the four sealed fields
// {status, schemaVersion, payload, evidenceRef} and returns its SHA-256 hash.
// Uses preserved raw JSON when available (from deserialization) to avoid re-marshaling
// artifacts that would invalidate the signature.
func computeSealDigest(resp *models.TLResponse) ([32]byte, error) {
	statusJSON, err := rawOrMarshal(resp.RawStatus, resp.Status)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: failed to marshal status: %w", err)
	}
	schemaJSON, err := rawOrMarshal(resp.RawSchemaVersion, resp.SchemaVersion)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: failed to marshal schemaVersion: %w", err)
	}
	payloadJSON, err := rawOrMarshal(resp.RawPayload, resp.Payload)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: failed to marshal payload: %w", err)
	}
	evidenceJSON, err := rawOrMarshal(resp.RawEvidenceRef, resp.EvidenceRef)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: failed to marshal evidenceRef: %w", err)
	}

	fields := map[string]json.RawMessage{
		"status":        statusJSON,
		"schemaVersion": schemaJSON,
		"payload":       payloadJSON,
		"evidenceRef":   evidenceJSON,
	}

	canonical, err := JCSCanonicalizeFields(fields)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: JCS canonicalization failed: %w", err)
	}

	return sha256.Sum256(canonical), nil
}

func rawOrMarshal(raw json.RawMessage, v any) (json.RawMessage, error) {
	if raw != nil {
		return raw, nil
	}
	return json.Marshal(v)
}

// VerifyReceiptSignature is a backward-compatible alias for VerifySealSignature.
func VerifyReceiptSignature(resp *models.TLResponse, trustedKey *ecdsa.PublicKey) error {
	return VerifySealSignature(resp, trustedKey)
}

// VerifySeal is a backward-compatible alias for VerifySealSignature.
func VerifySeal(resp *models.TLResponse, trustedKey *ecdsa.PublicKey) error {
	return VerifySealSignature(resp, trustedKey)
}

// ParseECDSAPublicKeyPEM parses an ECDSA public key from PEM-encoded data.
func ParseECDSAPublicKeyPEM(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("seal: failed to decode PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("seal: failed to parse public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("seal: expected ECDSA public key, got %T", pub)
	}

	return ecKey, nil
}
