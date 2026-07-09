package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func generateTestECDSAKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return key, string(pubPEM)
}

// signSeal computes the seal digest and signs it, returning the base64 signature.
func signSeal(t *testing.T, resp *models.TLResponse, key *ecdsa.PrivateKey) string {
	t.Helper()
	digest := computeTestSealDigest(t, resp)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("failed to sign seal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// computeTestSealDigest mirrors computeSealDigest for test use.
func computeTestSealDigest(t *testing.T, resp *models.TLResponse) [32]byte {
	t.Helper()
	statusJSON, _ := json.Marshal(resp.Status)
	schemaJSON, _ := json.Marshal(resp.SchemaVersion)
	payloadJSON, _ := json.Marshal(resp.Payload)
	evidenceJSON, _ := json.Marshal(resp.EvidenceRef)

	fields := map[string]json.RawMessage{
		"status":        statusJSON,
		"schemaVersion": schemaJSON,
		"payload":       payloadJSON,
		"evidenceRef":   evidenceJSON,
	}
	canonical, err := JCSCanonicalizeFields(fields)
	if err != nil {
		t.Fatalf("JCS canonicalization failed: %v", err)
	}
	return sha256.Sum256(canonical)
}

func newTestTLResponse(t *testing.T, key *ecdsa.PrivateKey) *models.TLResponse {
	t.Helper()

	_, pubPEM := generateTestECDSAKey(t)
	_ = pubPEM

	// Build PEM for the signing key
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	resp := &models.TLResponse{
		Status:        "ACTIVE",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			LogID:            "log-001",
			EventType:        "attestation",
			AgentName:        "ati://seal-test.example.com",
			AgentDisplayName: "seal-agent",
			AgentHost:        "seal-test.example.com",
			AgentID:          "ans-seal-001",
			AgentStatus:      "ACTIVE",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "SHA256:abcdef",
			},
		},
		EvidenceRef: models.EvidenceRef{
			EvidenceID:   "ev-001",
			SubmitterID:  "submitter-001",
			EvidenceType: "agent-attestation",
		},
		Seal: models.TLSeal{
			Canonicalization:   "JCS",
			DigestAlgorithm:    "SHA-256",
			SignatureAlgorithm: "ES256",
			SignatureEncoding:  "base64",
			KeyID:              "seal-kid",
			PublicKey:          keyPEM,
		},
		MerkleProof: models.MerkleProof{
			LeafHash:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LeafIndex: 10,
			TreeSize:  50,
		},
	}

	resp.Seal.Signature = signSeal(t, resp, key)
	return resp
}

func TestVerifySealSignature_Success(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)

	err := VerifySealSignature(resp, &key.PublicKey)
	if err != nil {
		t.Fatalf("VerifySealSignature() error = %v", err)
	}
}

func TestVerifySealSignature_EmbeddedKey(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)

	err := VerifySealSignature(resp, nil)
	if err != nil {
		t.Fatalf("VerifySealSignature() with embedded key error = %v", err)
	}
}

func TestVerifySealSignature_WrongKey(t *testing.T) {
	sigKey, _ := generateTestECDSAKey(t)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	resp := newTestTLResponse(t, sigKey)

	err := VerifySealSignature(resp, &wrongKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
}

func TestVerifySealSignature_TamperedPayload(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)

	resp.Payload.AgentName = "tampered"

	err := VerifySealSignature(resp, &key.PublicKey)
	if err == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
}

func TestVerifySealSignature_EmptySignature(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)
	resp.Seal.Signature = ""

	err := VerifySealSignature(resp, &key.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestVerifySealSignature_NilResponse(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	err := VerifySealSignature(nil, &key.PublicKey)
	if err == nil {
		t.Fatal("expected error for nil response")
	}
}

func TestVerifySealSignature_NoKeyAndNoEmbedded(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)
	resp.Seal.PublicKey = ""

	err := VerifySealSignature(resp, nil)
	if err == nil {
		t.Fatal("expected error when no trusted key and no embedded key")
	}
}

func TestVerifyReceiptSignature_BackwardCompat(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)

	err := VerifyReceiptSignature(resp, &key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyReceiptSignature() error = %v", err)
	}
}

func TestVerifySeal_BackwardCompat(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)

	err := VerifySeal(resp, &key.PublicKey)
	if err != nil {
		t.Fatalf("VerifySeal() error = %v", err)
	}
}

func TestParseECDSAPublicKeyPEM_Valid(t *testing.T) {
	_, pubPEM := generateTestECDSAKey(t)
	parsed, err := ParseECDSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseECDSAPublicKeyPEM() error = %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParseECDSAPublicKeyPEM_InvalidPEM(t *testing.T) {
	_, err := ParseECDSAPublicKeyPEM("not-valid-pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
