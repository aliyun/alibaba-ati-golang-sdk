package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// generateTestRSAKey generates a 2048-bit RSA key for tests. Production uses
// a 3072-bit key, but key size doesn't affect the algorithm-family dispatch
// under test, and 2048 bits keeps the test suite fast.
func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return key, string(pubPEM)
}

// signSealRSA computes the seal digest and signs it with PKCS#1 v1.5 (the
// "SHA-256withRSA" scheme the CNNIC TL platform's ati-tl-service key uses).
func signSealRSA(t *testing.T, resp *models.TLResponse, key *rsa.PrivateKey) string {
	t.Helper()
	digest := computeTestSealDigest(t, resp)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
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

func newTestTLResponseRSA(t *testing.T, key *rsa.PrivateKey) *models.TLResponse {
	t.Helper()

	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	resp := &models.TLResponse{
		Status:        "ACTIVE",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			LogID:            "log-002",
			EventType:        "attestation",
			AgentName:        "ati://seal-test-rsa.example.com",
			AgentDisplayName: "seal-agent-rsa",
			AgentHost:        "seal-test-rsa.example.com",
			AgentID:          "ans-seal-002",
			AgentStatus:      "ACTIVE",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "SHA256:abcdef",
			},
		},
		EvidenceRef: models.EvidenceRef{
			EvidenceID:   "ev-002",
			SubmitterID:  "submitter-002",
			EvidenceType: "agent-attestation",
		},
		Seal: models.TLSeal{
			Canonicalization:   "JCS",
			DigestAlgorithm:    "SHA-256",
			SignatureAlgorithm: SealAlgorithmRSA,
			SignatureEncoding:  "base64",
			KeyID:              "ati-tl-service",
			PublicKey:          keyPEM,
		},
		MerkleProof: models.MerkleProof{
			LeafHash:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			LeafIndex: 10,
			TreeSize:  50,
		},
	}

	resp.Seal.Signature = signSealRSA(t, resp, key)
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

func TestVerifySealSignature_RSA_Success(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	resp := newTestTLResponseRSA(t, key)

	err := VerifySealSignature(resp, &key.PublicKey)
	if err != nil {
		t.Fatalf("VerifySealSignature() error = %v", err)
	}
}

func TestVerifySealSignature_RSA_EmbeddedKey(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	resp := newTestTLResponseRSA(t, key)

	err := VerifySealSignature(resp, nil)
	if err != nil {
		t.Fatalf("VerifySealSignature() with embedded RSA key error = %v", err)
	}
}

func TestVerifySealSignature_RSA_WrongKey(t *testing.T) {
	sigKey, _ := generateTestRSAKey(t)
	wrongKey, _ := generateTestRSAKey(t)

	resp := newTestTLResponseRSA(t, sigKey)

	err := VerifySealSignature(resp, &wrongKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong RSA key, got nil")
	}
}

func TestVerifySealSignature_AlgorithmKeyTypeMismatch(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	resp := newTestTLResponseRSA(t, key)
	// Declare an ECDSA algorithm even though the key that will verify it is
	// RSA; this must be rejected as an algorithm-confusion attempt rather
	// than silently accepted or dispatched to the wrong verifier.
	resp.Seal.SignatureAlgorithm = "ES256"

	err := VerifySealSignature(resp, &key.PublicKey)
	if err == nil {
		t.Fatal("expected error for algorithm/key-type mismatch, got nil")
	}
}

func TestVerifySealSignature_UnsupportedKeyType(t *testing.T) {
	key, _ := generateTestECDSAKey(t)
	resp := newTestTLResponse(t, key)

	err := VerifySealSignature(resp, "not-a-key")
	if err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
}

func TestTLKeyStore_ECDSAAndRSAHit(t *testing.T) {
	ecKey, _ := generateTestECDSAKey(t)
	rsaKey, _ := generateTestRSAKey(t)

	store := NewTLKeyStore(map[string]crypto.PublicKey{
		"ati-tl-ecdsa-v1": &ecKey.PublicKey,
		"ati-tl-service":  &rsaKey.PublicKey,
	})

	ecResp := newTestTLResponse(t, ecKey)
	ecResp.Seal.KeyID = "ati-tl-ecdsa-v1"
	if err := VerifySealSignatureWithKeyStore(ecResp, store); err != nil {
		t.Fatalf("VerifySealSignatureWithKeyStore() ECDSA error = %v", err)
	}

	rsaResp := newTestTLResponseRSA(t, rsaKey)
	if err := VerifySealSignatureWithKeyStore(rsaResp, store); err != nil {
		t.Fatalf("VerifySealSignatureWithKeyStore() RSA error = %v", err)
	}
}

func TestTLKeyStore_UnknownKeyID(t *testing.T) {
	rsaKey, _ := generateTestRSAKey(t)
	store := NewTLKeyStore(map[string]crypto.PublicKey{
		"ati-tl-service": &rsaKey.PublicKey,
	})

	resp := newTestTLResponseRSA(t, rsaKey)
	resp.Seal.KeyID = "unknown-kid"

	err := VerifySealSignatureWithKeyStore(resp, store)
	if err == nil {
		t.Fatal("expected error for unknown key ID, got nil")
	}
}

func TestTLKeyStore_NilStore(t *testing.T) {
	rsaKey, _ := generateTestRSAKey(t)
	resp := newTestTLResponseRSA(t, rsaKey)

	err := VerifySealSignatureWithKeyStore(resp, nil)
	if err == nil {
		t.Fatal("expected error for nil key store, got nil")
	}
}

func TestTLKeyStore_GetOnNilReceiver(t *testing.T) {
	var store *TLKeyStore
	if _, ok := store.Get("any"); ok {
		t.Fatal("expected Get() on nil *TLKeyStore to report a miss")
	}
}
