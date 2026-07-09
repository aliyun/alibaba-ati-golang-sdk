package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestVerifyProducerSignature_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	resp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentID:   "ans-test-123",
			AgentName: "ati://test.example.com",
		},
		EvidenceRef: models.EvidenceRef{
			SubmitterID:       "test-kid",
			SignatureRequired: true,
		},
	}

	payloadJSON, _ := json.Marshal(resp.Payload)
	canonical, _ := JCSCanonicalize(payloadJSON)
	digest := sha256.Sum256(canonical)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	resp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(sig)

	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)

	if err := VerifyProducerSignature(resp, keys); err != nil {
		t.Errorf("VerifyProducerSignature() = %v, want nil", err)
	}
}

func TestVerifyProducerSignature_SkipWhenNotRequired(t *testing.T) {
	resp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentID: "ans-test-123",
		},
		EvidenceRef: models.EvidenceRef{
			SubmitterID:       "test-kid",
			SignatureRequired: false,
		},
	}

	if err := VerifyProducerSignature(resp, nil); err != nil {
		t.Errorf("VerifyProducerSignature() = %v, want nil (signatureRequired=false)", err)
	}
}

func TestVerifyProducerSignature_InvalidSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	resp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentID:   "ans-test-123",
			AgentName: "ati://test.example.com",
		},
		EvidenceRef: models.EvidenceRef{
			SubmitterID:       "test-kid",
			SignatureRequired: true,
			EvidenceHash:      base64.StdEncoding.EncodeToString([]byte("invalid-sig-data")),
		},
	}

	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)

	if err := VerifyProducerSignature(resp, keys); err == nil {
		t.Error("VerifyProducerSignature() = nil, want error for invalid signature")
	}
}

func TestVerifyProducerSignature_KeyNotFound(t *testing.T) {
	resp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentID: "ans-test-123",
		},
		EvidenceRef: models.EvidenceRef{
			SubmitterID:       "unknown-kid",
			SignatureRequired: true,
			EvidenceHash:      base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}

	keys := NewMockProducerKeyLookup()

	if err := VerifyProducerSignature(resp, keys); err == nil {
		t.Error("VerifyProducerSignature() = nil, want error for missing key")
	}
}

func TestVerifyProducerSignature_NilKeyLookup(t *testing.T) {
	resp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentID: "ans-test-123",
		},
		EvidenceRef: models.EvidenceRef{
			SubmitterID:       "test-kid",
			SignatureRequired: true,
		},
	}

	if err := VerifyProducerSignature(resp, nil); err == nil {
		t.Error("VerifyProducerSignature() = nil, want error for nil key lookup")
	}
}

func TestMockProducerKeyLookup_WithError(t *testing.T) {
	keys := NewMockProducerKeyLookup().WithError(fmt.Errorf("key revoked"))

	_, err := keys.GetProducerKey("any-kid")
	if err == nil {
		t.Error("GetProducerKey() = nil, want error")
	}
	if err.Error() != "key revoked" {
		t.Errorf("GetProducerKey() error = %q, want %q", err.Error(), "key revoked")
	}
}

func TestVerifyProducerSignature_TamperedPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	resp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentID:   "ans-test-123",
			AgentName: "ati://test.example.com",
		},
		EvidenceRef: models.EvidenceRef{
			SubmitterID:       "test-kid",
			SignatureRequired: true,
		},
	}

	payloadJSON, _ := json.Marshal(resp.Payload)
	canonical, _ := JCSCanonicalize(payloadJSON)
	digest := sha256.Sum256(canonical)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	resp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(sig)

	resp.Payload.AgentName = "ati://tampered.example.com"

	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)

	if err := VerifyProducerSignature(resp, keys); err == nil {
		t.Error("VerifyProducerSignature() = nil, want error for tampered payload")
	}
}
