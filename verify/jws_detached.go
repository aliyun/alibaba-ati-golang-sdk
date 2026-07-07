package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// JWS Detached Signature per spec §8.6.
// Uses ES256 (ECDSA P-256 + SHA-256) with detached payload for transaction-level non-repudiation.

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	B64 bool   `json:"b64"`
	Crit []string `json:"crit,omitempty"`
}

// VerifyJWSDetached verifies a JWS with detached payload (RFC 7797).
// The signature string is in compact serialization: header..signature (empty payload).
func VerifyJWSDetached(signature string, payload []byte, keys ProducerKeyLookup) error {
	parts := strings.Split(signature, ".")
	if len(parts) != 3 {
		return fmt.Errorf("jws: invalid compact serialization, expected 3 parts got %d", len(parts))
	}

	headerB64 := parts[0]
	if parts[1] != "" {
		return fmt.Errorf("jws: detached JWS must have empty payload part")
	}
	sigB64 := parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("jws: failed to decode header: %w", err)
	}

	var header jwsHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("jws: failed to parse header: %w", err)
	}

	if header.Alg != "ES256" {
		return fmt.Errorf("jws: unsupported algorithm %q, expected ES256", header.Alg)
	}

	if header.B64 != false {
		return fmt.Errorf("jws: b64 must be false for detached payload")
	}

	pubKey, err := keys.GetProducerKey(header.Kid)
	if err != nil {
		return fmt.Errorf("jws: failed to get key for kid %q: %w", header.Kid, err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("jws: failed to decode signature: %w", err)
	}

	// For detached unencoded payload (b64=false), signing input is: header.payload
	signingInput := headerB64 + "." + string(payload)
	digest := sha256.Sum256([]byte(signingInput))

	// ES256 signature is r || s, each 32 bytes
	if len(sigBytes) != 64 {
		return fmt.Errorf("jws: invalid ES256 signature length %d, expected 64", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pubKey, digest[:], r, s) {
		return fmt.Errorf("jws: signature verification failed")
	}

	return nil
}

// CreateJWSDetached creates a JWS with detached payload (RFC 7797).
// Returns compact serialization: header..signature (empty payload section).
func CreateJWSDetached(payload []byte, privateKey *ecdsa.PrivateKey, kid string) (string, error) {
	if privateKey.Curve != elliptic.P256() {
		return "", fmt.Errorf("jws: key must be P-256 for ES256")
	}

	header := jwsHeader{
		Alg:  "ES256",
		Kid:  kid,
		B64:  false,
		Crit: []string{"b64"},
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jws: failed to marshal header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Signing input for detached unencoded payload
	signingInput := headerB64 + "." + string(payload)
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("jws: signing failed: %w", err)
	}

	// Encode r and s as fixed-size 32-byte values
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return headerB64 + ".." + sigB64, nil
}
