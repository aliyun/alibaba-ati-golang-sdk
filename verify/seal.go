package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// SealAlgorithmECDSA and SealAlgorithmRSA are the seal.signatureAlgorithm values
// the CNNIC TL platform reports for its two concurrently-trusted signing keys:
// the legacy ECDSA P-256 key (ati-tl-ecdsa-v1) and the RSA-3072 key
// (ati-tl-service) that superseded it for agents registered from 2026-08-17.
// Responses have also been observed using the JOSE names ES256/RS256 for the
// same two algorithm families; sealAlgorithmFamily recognizes both spellings.
const (
	SealAlgorithmECDSA = "SHA-256withECDSA"
	SealAlgorithmRSA   = "SHA-256withRSA"
)

// sealAlgorithmFamily classifies a seal.signatureAlgorithm value as "ECDSA",
// "RSA", "" (not reported), or "unknown" (reported but unrecognized).
func sealAlgorithmFamily(algorithm string) string {
	if algorithm == "" {
		return ""
	}
	upper := strings.ToUpper(algorithm)
	switch upper {
	case "ES256", "ES384", "ES512":
		return "ECDSA"
	case "RS256", "RS384", "RS512":
		return "RSA"
	}
	switch {
	case strings.Contains(upper, "ECDSA"):
		return "ECDSA"
	case strings.Contains(upper, "RSA"):
		return "RSA"
	default:
		return "unknown"
	}
}

// VerifySealSignature verifies the CNNIC TL seal signature over the four sealed fields:
// JCS({status, schemaVersion, payload, evidenceRef}) -> SHA-256 -> ECDSA P-256 or RSA-3072
// (PKCS#1 v1.5), depending on which key signed the seal.
// When trustedKey is nil, the embedded public key from resp.Seal.PublicKey is used.
func VerifySealSignature(resp *models.TLResponse, trustedKey crypto.PublicKey) error {
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
		parsed, err := ParsePublicKeyPEM(seal.PublicKey)
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

	return verifySealDigest(key, seal.SignatureAlgorithm, digest, sigBytes)
}

// verifySealDigest dispatches signature verification based on the concrete
// type of key. seal.signatureAlgorithm (when present) is cross-checked
// against the key type to reject algorithm-confusion attempts, but a missing
// value (older responses) does not block verification.
func verifySealDigest(key crypto.PublicKey, algorithm string, digest [32]byte, sigBytes []byte) error {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if fam := sealAlgorithmFamily(algorithm); fam != "" && fam != "ECDSA" {
			return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
				fmt.Sprintf("seal declares signatureAlgorithm %q but key is ECDSA", algorithm))
		}
		if !ecdsa.VerifyASN1(k, digest[:], sigBytes) {
			return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
				"seal ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		if fam := sealAlgorithmFamily(algorithm); fam != "" && fam != "RSA" {
			return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
				fmt.Sprintf("seal declares signatureAlgorithm %q but key is RSA", algorithm))
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sigBytes); err != nil {
			return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
				"seal RSA signature verification failed", WithCause(err))
		}
		return nil
	default:
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			fmt.Sprintf("unsupported TL public key type %T", key))
	}
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
func VerifyReceiptSignature(resp *models.TLResponse, trustedKey crypto.PublicKey) error {
	return VerifySealSignature(resp, trustedKey)
}

// VerifySeal is a backward-compatible alias for VerifySealSignature.
func VerifySeal(resp *models.TLResponse, trustedKey crypto.PublicKey) error {
	return VerifySealSignature(resp, trustedKey)
}

// ParsePublicKeyPEM parses an ECDSA or RSA public key from PEM-encoded PKIX data.
func ParsePublicKeyPEM(pemData string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("seal: failed to decode PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("seal: failed to parse public key: %w", err)
	}

	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("seal: expected ECDSA or RSA public key, got %T", pub)
	}
}

// ParseECDSAPublicKeyPEM parses an ECDSA public key from PEM-encoded data.
//
// Deprecated: use ParsePublicKeyPEM, which also accepts RSA keys now that the
// TL platform signs seals with either an ECDSA or an RSA-3072 key.
func ParseECDSAPublicKeyPEM(pemData string) (*ecdsa.PublicKey, error) {
	pub, err := ParsePublicKeyPEM(pemData)
	if err != nil {
		return nil, err
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("seal: expected ECDSA public key, got %T", pub)
	}
	return ecKey, nil
}

// TLKeyStore is a key-ID-indexed trust store for TL seal-signing public keys.
// It lets a caller pin multiple concurrently-trusted platform keys (e.g. the
// legacy ECDSA key alongside the newer RSA-3072 key) instead of a single
// trustedKey, so seals from either era verify without guessing which key
// signed a given response.
type TLKeyStore struct {
	keys map[string]crypto.PublicKey
}

// NewTLKeyStore creates a TLKeyStore from a map of key ID (seal.keyId) to public key.
func NewTLKeyStore(keys map[string]crypto.PublicKey) *TLKeyStore {
	copied := make(map[string]crypto.PublicKey, len(keys))
	for kid, key := range keys {
		copied[kid] = key
	}
	return &TLKeyStore{keys: copied}
}

// Get looks up a trusted public key by key ID.
func (s *TLKeyStore) Get(kid string) (crypto.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	key, ok := s.keys[kid]
	return key, ok
}

// VerifySealSignatureWithKeyStore verifies a seal signature using a key looked
// up by resp.Seal.KeyID in store. Unlike VerifySealSignature's nil-trustedKey
// TOFU fallback, an unknown key ID is always rejected rather than falling
// back to the embedded seal.PublicKey.
func VerifySealSignatureWithKeyStore(resp *models.TLResponse, store *TLKeyStore) error {
	if resp == nil {
		return errors.New("seal: nil TL response")
	}
	if store == nil {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"no TL key store configured")
	}
	kid := resp.Seal.KeyID
	if kid == "" {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"seal has no key ID")
	}
	key, ok := store.Get(kid)
	if !ok {
		return NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			fmt.Sprintf("unknown TL key ID %q", kid))
	}
	return VerifySealSignature(resp, key)
}
