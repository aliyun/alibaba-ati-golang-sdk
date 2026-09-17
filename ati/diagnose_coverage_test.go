package ati

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

func TestDiagnose_SealSignatureFail(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-seal-fail"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/" + agentID, Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	// Build TL response with invalid seal signature
	tlResp := buildTLLogResponseWithBadSeal(t, agentID, "ACTIVE")
	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}

	// Step 5 (Seal Signature) should FAIL
	if len(result.Steps) < 5 {
		t.Fatalf("got %d steps, want at least 5", len(result.Steps))
	}
	step5 := result.Steps[4]
	if step5.Status != "FAIL" {
		t.Errorf("step 5 (Seal Signature) status = %q, want FAIL", step5.Status)
	}
	if step5.Error == "" {
		t.Error("step 5 should have an error message")
	}
}

func TestDiagnose_TerminalAgentStatus(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-terminal"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/" + agentID, Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	// Build TL response with terminal status (REVOKED)
	tlResp := buildTLLogResponse(t, agentID, "REVOKED")
	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}

	// Step 9 (Agent Status) should FAIL for terminal status
	if len(result.Steps) < 9 {
		t.Fatalf("got %d steps, want 9", len(result.Steps))
	}
	step9 := result.Steps[8]
	if step9.Status != "FAIL" {
		t.Errorf("step 9 (Agent Status) status = %q, want FAIL for terminal status", step9.Status)
	}
	if step9.Error == "" {
		t.Error("step 9 should have an error for terminal status")
	}
}

func TestDiagnose_EmptyAgentStatus(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-no-status"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/" + agentID, Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	// Build TL response with empty agent status
	tlResp := buildTLLogResponse(t, agentID, "ACTIVE")
	tlResp.Payload.AgentStatus = "" // empty status
	// Re-sign after modification
	resignTLResponse(t, tlResp)
	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}

	// Step 9 (Agent Status) should SKIP for empty status
	if len(result.Steps) < 9 {
		t.Fatalf("got %d steps, want 9", len(result.Steps))
	}
	step9 := result.Steps[8]
	if step9.Status != "SKIP" {
		t.Errorf("step 9 (Agent Status) status = %q, want SKIP for empty status", step9.Status)
	}
}

func TestDiagnose_SignatureRequiredTrue(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-sig-req"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/" + agentID, Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	tlResp := buildTLLogResponse(t, agentID, "ACTIVE")
	tlResp.EvidenceRef.SignatureRequired = true
	resignTLResponse(t, tlResp)
	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}

	// Step 7 (Producer Signature) should be SKIP with signatureRequired=true
	if len(result.Steps) < 7 {
		t.Fatalf("got %d steps, want at least 7", len(result.Steps))
	}
	step7 := result.Steps[6]
	if step7.Status != "SKIP" {
		t.Errorf("step 7 (Producer Signature) status = %q, want SKIP", step7.Status)
	}
	if step7.Detail == "" {
		t.Error("step 7 should have detail about SubmitterID")
	}
}

func TestDiagnose_CertFingerprints(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-fp"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/" + agentID, Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	tlResp := buildTLLogResponse(t, agentID, "ACTIVE")
	// Ensure cert fingerprints are set
	tlResp.Payload.Certificates.IdentityCertFingerprint = "SHA256:aabbccdd"
	tlResp.Payload.Certificates.ServerCertFingerprint = "SHA256:eeff0011"
	resignTLResponse(t, tlResp)
	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}

	// Step 8 (Certificate Fingerprints) should PASS
	if len(result.Steps) < 8 {
		t.Fatalf("got %d steps, want at least 8", len(result.Steps))
	}
	step8 := result.Steps[7]
	if step8.Status != "PASS" {
		t.Errorf("step 8 (Certificate Fingerprints) status = %q, want PASS", step8.Status)
	}
}

func TestDiagnose_MerkleProofFail(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-merkle-fail"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/" + agentID, Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	tlResp := buildTLLogResponse(t, agentID, "ACTIVE")
	// Corrupt the merkle proof
	tlResp.MerkleProof.RootHash = "0000000000000000000000000000000000000000000000000000000000000000"
	tlResp.MerkleProof.LeafHash = "1111111111111111111111111111111111111111111111111111111111111111"
	tlResp.MerkleProof.TreeSize = 10
	tlResp.MerkleProof.LeafIndex = 5
	tlResp.MerkleProof.Path = []string{"aabbccdd"}
	resignTLResponse(t, tlResp)
	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}

	// Step 6 (Merkle Proof) should FAIL
	if len(result.Steps) < 6 {
		t.Fatalf("got %d steps, want at least 6", len(result.Steps))
	}
	step6 := result.Steps[5]
	if step6.Status != "FAIL" {
		t.Errorf("step 6 (Merkle Inclusion Proof) status = %q, want FAIL", step6.Status)
	}
}

func TestDiagnose_StringOutputWithSkip(t *testing.T) {
	result := &DiagnoseResult{
		Host:      "agent.example.com",
		Timestamp: "2026-01-01T00:00:00Z",
		Steps: []DiagnoseStep{
			{Name: "Host Validation", Status: "PASS", Duration: "1ms", Detail: "ok"},
			{Name: "Skipped Step", Status: "SKIP", Duration: "0s", Detail: "not applicable"},
		},
		Summary: "PARTIAL",
	}

	s := result.String()
	if !contains(s, "[SKIP]") {
		t.Error("String() should contain [SKIP] for SKIP status")
	}
}

// helpers

func buildTLLogResponseWithBadSeal(t *testing.T, agentID, status string) *models.TLResponse {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	lh := sha256.Sum256([]byte("diagnose-test-leaf"))
	leafHex := hex.EncodeToString(lh[:])

	return &models.TLResponse{
		Status:        status,
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			LogID:            "log-diag-001",
			EventType:        "attestation",
			AgentID:          agentID,
			AgentName:        "ati://test-agent.example.com",
			AgentDisplayName: "test-agent",
			AgentHost:        "test-agent.example.com",
			AgentStatus:      status,
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "SHA256:abcdef",
			},
		},
		EvidenceRef: models.EvidenceRef{
			EvidenceID:        "ev-diag-001",
			SubmitterID:       "producer-kid",
			EvidenceType:      "agent-attestation",
			SignatureRequired: false,
		},
		Seal: models.TLSeal{
			Canonicalization:   "JCS",
			DigestAlgorithm:    "SHA-256",
			SignatureAlgorithm: "ES256",
			SignatureEncoding:  "base64",
			KeyID:              "test-kid",
			PublicKey:          keyPEM,
			Signature:          base64.StdEncoding.EncodeToString([]byte("invalid-signature")),
		},
		MerkleProof: models.MerkleProof{
			LeafHash:  leafHex,
			RootHash:  leafHex,
			LeafIndex: 0,
			TreeSize:  1,
			Path:      []string{},
		},
	}
}

func resignTLResponse(t *testing.T, resp *models.TLResponse) {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	resp.Seal.PublicKey = keyPEM

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
	canonical, _ := verify.JCSCanonicalizeFields(fields)
	digest := sha256.Sum256(canonical)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	resp.Seal.Signature = base64.StdEncoding.EncodeToString(sig)
}

