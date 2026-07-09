package verify

import (
	"context"
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

func buildTestTLResponse(t *testing.T, tlKey *ecdsa.PrivateKey, producerKey *ecdsa.PrivateKey, fingerprint string) *models.TLResponse {
	t.Helper()

	pubDER, _ := x509.MarshalPKIXPublicKey(&tlKey.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	leafHash := hexHash([]byte("gold-test-leaf"))

	resp := &models.TLResponse{
		Status:        "ACTIVE",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			LogID:            "log-gold-001",
			EventType:        "attestation",
			AgentID:          "ans-gold-001",
			AgentName:        "ati://agent.example.com",
			AgentDisplayName: "test-agent",
			AgentHost:        "agent.example.com",
			Version:          "v1.0.0",
			AgentStatus:      "ACTIVE",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: fingerprint,
			},
		},
		EvidenceRef: models.EvidenceRef{
			EvidenceID:        "ev-gold-001",
			SubmitterID:       "producer-kid-1",
			EvidenceType:      "agent-attestation",
			SignatureRequired: producerKey != nil,
		},
		Seal: models.TLSeal{
			Canonicalization:   "JCS",
			DigestAlgorithm:    "SHA-256",
			SignatureAlgorithm: "ES256",
			SignatureEncoding:  "base64",
			KeyID:              "tl-kid-1",
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

func goldTestConfig(t *testing.T, tlKey *ecdsa.PrivateKey, producerKey *ecdsa.PrivateKey, resolver DNSResolver, tlogClient TransparencyLogClient) *GoldVerifierConfig {
	t.Helper()
	cfg := &GoldVerifierConfig{
		TLBaseURL:   "https://tl.test.local/ans/api/v1",
		TLPublicKey: &tlKey.PublicKey,
		DNSResolver: resolver,
		TLogClient:  tlogClient,
	}
	if producerKey != nil {
		cfg.ProducerKeys = NewMockProducerKeyLookup().WithKey("producer-kid-1", &producerKey.PublicKey)
	}
	return cfg
}

func TestVerifyGold_Success(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("test-cert-der"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() failed: %v", result.Error)
	}
	if result.TrustLevel == TrustLevelNone {
		t.Error("TrustLevel = NONE, want higher")
	}
}

func TestVerifyGold_DNSNotFound(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockResolver := NewMockDNSResolver()
	mockTLog := NewMockTransparencyLogClient()

	fqdn, _ := models.NewFqdn("unknown.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	cert := &CertIdentity{}
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Error("VerifyGold() should fail when no DNS records")
	}
}

func TestVerifyGold_TLFetchError(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ag-gold-1", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})
	mockTLog := NewMockTransparencyLogClient()

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	cert := &CertIdentity{}
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Error("VerifyGold() should fail when TL fetch fails")
	}
}

func TestVerifyGold_SealSigFails(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("test-cert-der"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, wrongKey, producerKey, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Error("VerifyGold() should fail with bad seal signature")
	}
}

func TestVerifyGold_FingerprintMismatch(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fpInTL := CertFingerprintFromDER([]byte("tl-cert-der"))
	fpActual := CertFingerprintFromDER([]byte("actual-cert-der"))
	cert := &CertIdentity{Fingerprint: fpActual}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fpInTL.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Error("VerifyGold() should fail with fingerprint mismatch")
	}
}

func TestVerifyGold_RevokedStatus(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("test-cert-der"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())
	tlResp.Payload.AgentStatus = "REVOKED"
	// Re-sign producer first (modifies evidenceRef), then seal
	payloadJSON, _ := json.Marshal(tlResp.Payload)
	canonical, _ := JCSCanonicalize(payloadJSON)
	producerDigest := sha256.Sum256(canonical)
	producerSig, _ := ecdsa.SignASN1(rand.Reader, producerKey, producerDigest[:])
	tlResp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(producerSig)
	tlResp.Seal.Signature = signSeal(t, tlResp, tlKey)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Error("VerifyGold() should fail with REVOKED status")
	}
}

func TestVerifyGold_DeprecatedStatus(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("test-cert-der"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())
	tlResp.Payload.AgentStatus = "DEPRECATED"
	payloadJSON2, _ := json.Marshal(tlResp.Payload)
	canonical2, _ := JCSCanonicalize(payloadJSON2)
	producerDigest2 := sha256.Sum256(canonical2)
	producerSig2, _ := ecdsa.SignASN1(rand.Reader, producerKey, producerDigest2[:])
	tlResp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(producerSig2)
	tlResp.Seal.Signature = signSeal(t, tlResp, tlKey)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() should succeed with DEPRECATED (non-terminal): %v", result.Error)
	}
	if len(result.Warnings) == 0 {
		t.Error("expected DEPRECATED warning")
	}
}

// hexHash helper is defined in merkle_test.go (same package)
// signSeal and computeTestSealDigest are defined in seal_test.go (same package)
