package verify

import (
	"context"
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

func buildOfflineTestResponseRSA(t *testing.T, tlKey *rsa.PrivateKey, fingerprint string) *models.TLResponse {
	t.Helper()

	pubDER, _ := x509.MarshalPKIXPublicKey(&tlKey.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	leafHash := hexHash([]byte("offline-test-leaf-rsa"))

	resp := &models.TLResponse{
		Status:        "ACTIVE",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			LogID:            "log-offline-002",
			EventType:        "attestation",
			AgentID:          "ans-offline-002",
			AgentName:        "ati://offline-rsa.example.com",
			AgentDisplayName: "offline-agent-rsa",
			AgentHost:        "offline-rsa.example.com",
			AgentStatus:      "ACTIVE",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: fingerprint,
			},
		},
		EvidenceRef: models.EvidenceRef{
			EvidenceID:   "ev-offline-002",
			SubmitterID:  "producer-kid",
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
			LeafHash:  leafHash,
			RootHash:  leafHash,
			LeafIndex: 0,
			TreeSize:  1,
			Path:      []string{},
		},
	}

	resp.Seal.Signature = signSealRSA(t, resp, tlKey)

	return resp
}

func buildOfflineTestResponse(t *testing.T, tlKey, producerKey *ecdsa.PrivateKey, fingerprint string) *models.TLResponse {
	t.Helper()

	pubDER, _ := x509.MarshalPKIXPublicKey(&tlKey.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	leafHash := hexHash([]byte("offline-test-leaf"))

	resp := &models.TLResponse{
		Status:        "ACTIVE",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			LogID:            "log-offline-001",
			EventType:        "attestation",
			AgentID:          "ans-offline-001",
			AgentName:        "ati://offline.example.com",
			AgentDisplayName: "offline-agent",
			AgentHost:        "offline.example.com",
			AgentStatus:      "ACTIVE",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: fingerprint,
			},
		},
		EvidenceRef: models.EvidenceRef{
			EvidenceID:        "ev-offline-001",
			SubmitterID:       "producer-kid",
			EvidenceType:      "agent-attestation",
			SignatureRequired: producerKey != nil,
		},
		Seal: models.TLSeal{
			Canonicalization:   "JCS",
			DigestAlgorithm:    "SHA-256",
			SignatureAlgorithm: "ES256",
			SignatureEncoding:  "base64",
			KeyID:              "tl-kid",
			PublicKey:          keyPEM,
		},
		MerkleProof: models.MerkleProof{
			LeafHash:  leafHash,
			RootHash:  leafHash,
			LeafIndex: 0,
			TreeSize:  1,
			Path:      []string{},
		},
	}

	if producerKey != nil {
		payloadJSON, _ := json.Marshal(resp.Payload)
		canonical, _ := JCSCanonicalize(payloadJSON)
		producerDigest := sha256.Sum256(canonical)
		producerSig, _ := ecdsa.SignASN1(rand.Reader, producerKey, producerDigest[:])
		resp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(producerSig)
	}

	resp.Seal.Signature = signSeal(t, resp, tlKey)

	return resp
}

func TestOfflineVerifier_VerifyOffline_Success(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("offline-cert-data"))
	resp := buildOfflineTestResponse(t, tlKey, producerKey, fp.String())

	respJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	cert := &CertIdentity{Fingerprint: fp}
	keys := NewMockProducerKeyLookup().WithKey("producer-kid", &producerKey.PublicKey)
	verifier := NewOfflineVerifier(&tlKey.PublicKey, keys)

	result, err := verifier.VerifyOffline(context.Background(), respJSON, cert)
	if err != nil {
		t.Fatalf("VerifyOffline() error = %v", err)
	}
	if !result.IsSuccess() {
		t.Errorf("VerifyOffline() result not successful: %+v", result.Error)
	}
	if len(result.Warnings) == 0 {
		t.Error("expected revocation status unknown warning")
	}
}

func TestOfflineVerifier_VerifyOffline_EmptyResponse(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifier := NewOfflineVerifier(&tlKey.PublicKey, nil)

	_, err := verifier.VerifyOffline(context.Background(), nil, nil)
	if err == nil {
		t.Error("VerifyOffline() = nil, want error for empty response")
	}
}

func TestOfflineVerifier_VerifyOffline_InvalidJSON(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifier := NewOfflineVerifier(&tlKey.PublicKey, nil)

	_, err := verifier.VerifyOffline(context.Background(), []byte("{invalid"), nil)
	if err == nil {
		t.Error("VerifyOffline() = nil, want error for invalid JSON")
	}
}

func TestOfflineVerifier_VerifyOffline_BadSealSig(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("test-cert"))
	resp := buildOfflineTestResponse(t, wrongKey, producerKey, fp.String())
	respJSON, _ := json.Marshal(resp)

	cert := &CertIdentity{Fingerprint: fp}
	keys := NewMockProducerKeyLookup().WithKey("producer-kid", &producerKey.PublicKey)
	verifier := NewOfflineVerifier(&tlKey.PublicKey, keys)

	result, err := verifier.VerifyOffline(context.Background(), respJSON, cert)
	if err != nil {
		t.Fatalf("VerifyOffline() unexpected error: %v", err)
	}
	if result.IsSuccess() {
		t.Error("VerifyOffline() should fail with bad seal signature")
	}
}

func TestOfflineVerifier_VerifyOffline_FingerprintMismatch(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fpInTL := CertFingerprintFromDER([]byte("in-tl-cert"))
	resp := buildOfflineTestResponse(t, tlKey, producerKey, fpInTL.String())
	respJSON, _ := json.Marshal(resp)

	fpActual := CertFingerprintFromDER([]byte("different-cert"))
	cert := &CertIdentity{Fingerprint: fpActual}
	keys := NewMockProducerKeyLookup().WithKey("producer-kid", &producerKey.PublicKey)
	verifier := NewOfflineVerifier(&tlKey.PublicKey, keys)

	result, err := verifier.VerifyOffline(context.Background(), respJSON, cert)
	if err != nil {
		t.Fatalf("VerifyOffline() unexpected error: %v", err)
	}
	if result.IsSuccess() {
		t.Error("VerifyOffline() should fail with fingerprint mismatch")
	}
}

func TestOfflineVerifier_VerifyOffline_NoProducerKeys(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("test-cert"))
	resp := buildOfflineTestResponse(t, tlKey, producerKey, fp.String())
	respJSON, _ := json.Marshal(resp)

	cert := &CertIdentity{Fingerprint: fp}
	verifier := NewOfflineVerifier(&tlKey.PublicKey, nil)

	result, err := verifier.VerifyOffline(context.Background(), respJSON, cert)
	if err != nil {
		t.Fatalf("VerifyOffline() error = %v", err)
	}
	if !result.IsSuccess() {
		t.Errorf("VerifyOffline() should succeed without producer keys: %v", result.Error)
	}
}

func TestOfflineVerifier_VerifyOffline_KeyStore_DualAlgorithm(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	store := NewTLKeyStore(map[string]crypto.PublicKey{
		"ati-tl-ecdsa-v1": &ecKey.PublicKey,
		"ati-tl-service":  &rsaKey.PublicKey,
	})

	fp := CertFingerprintFromDER([]byte("offline-cert-data-keystore"))
	cert := &CertIdentity{Fingerprint: fp}
	verifier := NewOfflineVerifierWithKeyStore(store, nil)

	// Legacy ECDSA-signed response.
	ecResp := buildOfflineTestResponse(t, ecKey, nil, fp.String())
	ecResp.Seal.KeyID = "ati-tl-ecdsa-v1"
	ecRespJSON, _ := json.Marshal(ecResp)

	result, err := verifier.VerifyOffline(context.Background(), ecRespJSON, cert)
	if err != nil {
		t.Fatalf("VerifyOffline() ECDSA via TLKeyStore error = %v", err)
	}
	if !result.IsSuccess() {
		t.Fatalf("VerifyOffline() ECDSA via TLKeyStore failed: %v", result.Error)
	}

	// RSA-3072-signed response through the same key store.
	rsaResp := buildOfflineTestResponseRSA(t, rsaKey, fp.String())
	rsaRespJSON, _ := json.Marshal(rsaResp)

	result2, err := verifier.VerifyOffline(context.Background(), rsaRespJSON, cert)
	if err != nil {
		t.Fatalf("VerifyOffline() RSA via TLKeyStore error = %v", err)
	}
	if !result2.IsSuccess() {
		t.Fatalf("VerifyOffline() RSA via TLKeyStore failed: %v", result2.Error)
	}
}
