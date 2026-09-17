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
	"errors"
	"strings"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

func TestDiagnose_AllPass(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-12345"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		}).
		WithRecords(host, []verify.ATIBadgeRecord{
			{URL: "https://tl.example.com/badge/ag-12345", Version: ptrVersion(models.NewVersion(1, 0, 0))},
		})

	tlResp := buildTLLogResponse(t, agentID, "ACTIVE")
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

	if result.Host != host {
		t.Errorf("Host = %q, want %q", result.Host, host)
	}
	if len(result.Steps) != 9 {
		t.Fatalf("got %d steps, want 9", len(result.Steps))
	}

	for i := 0; i < 4; i++ {
		if result.Steps[i].Status != "PASS" {
			t.Errorf("step[%d] %q status = %q, want PASS (error: %s)",
				i, result.Steps[i].Name, result.Steps[i].Status, result.Steps[i].Error)
		}
	}
	if result.Steps[4].Status != "PASS" {
		t.Errorf("step[4] %q status = %q, want PASS (error: %s)",
			result.Steps[4].Name, result.Steps[4].Status, result.Steps[4].Error)
	}
	if result.Steps[5].Status != "PASS" {
		t.Errorf("step[5] %q status = %q, want PASS (error: %s)",
			result.Steps[5].Name, result.Steps[5].Status, result.Steps[5].Error)
	}
}

func TestDiagnose_InvalidHost(t *testing.T) {
	result, err := Diagnose(context.Background(), "!!!invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "FAIL (invalid host)" {
		t.Errorf("Summary = %q, want %q", result.Summary, "FAIL (invalid host)")
	}
	if len(result.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(result.Steps))
	}
	if result.Steps[0].Status != "FAIL" {
		t.Errorf("step status = %q, want FAIL", result.Steps[0].Status)
	}
}

func TestDiagnose_DNSDiscoveryError(t *testing.T) {
	host := "agent.example.com"
	dns := verify.NewMockDNSResolver().
		WithError(host, errors.New("SERVFAIL"))

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "FAIL (DNS discovery error)" {
		t.Errorf("Summary = %q, want %q", result.Summary, "FAIL (DNS discovery error)")
	}
	if result.Steps[1].Status != "FAIL" {
		t.Errorf("DNS step status = %q, want FAIL", result.Steps[1].Status)
	}
}

func TestDiagnose_DNSDiscoveryNotFound(t *testing.T) {
	host := "agent.example.com"
	dns := verify.NewMockDNSResolver()

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "FAIL (not an ATI agent)" {
		t.Errorf("Summary = %q, want %q", result.Summary, "FAIL (not an ATI agent)")
	}
}

func TestDiagnose_TLFetchError(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-12345"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	tlURL := "https://tl.test/ans/api/v1/tl/agents/" + agentID + "/logs/latest"
	tlog := verify.NewMockTransparencyLogClient().WithError(tlURL, errors.New("connection refused"))

	result, err := Diagnose(context.Background(), host,
		WithDiagnoseDNSResolver(dns),
		WithDiagnoseTLogClient(tlog),
		withDiagnoseTLBaseURL("https://tl.test/ans/api/v1"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Summary == "ALL PASS" {
		t.Error("expected partial fail when TL fetch errors")
	}
	step4 := result.Steps[3]
	if step4.Status != "FAIL" {
		t.Errorf("TL step status = %q, want FAIL", step4.Status)
	}
	for _, idx := range []int{4, 5} {
		if result.Steps[idx].Status != "SKIP" {
			t.Errorf("step[%d] status = %q, want SKIP", idx, result.Steps[idx].Status)
		}
	}
}

func TestDiagnose_NoBadgeRecord(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-12345"

	dns := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: agentID, RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	tlResp := buildTLLogResponse(t, agentID, "ACTIVE")
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

	step3 := result.Steps[2]
	if step3.Status != "SKIP" {
		t.Errorf("badge step status = %q, want SKIP", step3.Status)
	}
}

func TestDiagnose_StringOutput(t *testing.T) {
	result := &DiagnoseResult{
		Host:      "agent.example.com",
		Timestamp: "2026-01-01T00:00:00Z",
		Steps: []DiagnoseStep{
			{Name: "Host Validation", Status: "PASS", Duration: "1ms", Detail: "FQDN: agent.example.com."},
			{Name: "DNS Discovery", Status: "FAIL", Duration: "5ms", Error: "timeout"},
		},
		Summary: "PARTIAL FAIL",
	}

	s := result.String()
	if !strings.Contains(s, "agent.example.com") {
		t.Error("String() should contain host")
	}
	if !strings.Contains(s, "[OK]") {
		t.Error("String() should contain [OK] for PASS")
	}
	if !strings.Contains(s, "[FAIL]") {
		t.Error("String() should contain [FAIL] for FAIL")
	}
	if !strings.Contains(s, "Error: timeout") {
		t.Error("String() should contain error detail")
	}
	if !strings.Contains(s, "PARTIAL FAIL") {
		t.Error("String() should contain summary")
	}
}

func TestDiagnose_JSONOutput(t *testing.T) {
	result := &DiagnoseResult{
		Host:      "agent.example.com",
		Timestamp: "2026-01-01T00:00:00Z",
		Steps: []DiagnoseStep{
			{Name: "Host Validation", Status: "PASS", Duration: "1ms"},
		},
		Summary: "ALL PASS",
	}

	jsonStr := result.JSON()
	var parsed DiagnoseResult
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("JSON() output is not valid JSON: %v", err)
	}
	if parsed.Host != "agent.example.com" {
		t.Errorf("parsed host = %q, want %q", parsed.Host, "agent.example.com")
	}
	if len(parsed.Steps) != 1 {
		t.Fatalf("parsed steps count = %d, want 1", len(parsed.Steps))
	}
}

func TestDiagnose_Options(t *testing.T) {
	cfg := &diagnoseConfig{}

	customDNS := verify.NewMockDNSResolver()
	customTLog := verify.NewMockTransparencyLogClient()

	WithDiagnoseDNSResolver(customDNS)(cfg)
	WithDiagnoseTLogClient(customTLog)(cfg)
	withDiagnoseTLBaseURL("https://custom.tl/api")(cfg)

	if cfg.dnsResolver != customDNS {
		t.Error("WithDiagnoseDNSResolver did not set resolver")
	}
	if cfg.tlogClient != customTLog {
		t.Error("WithDiagnoseTLogClient did not set client")
	}
	if cfg.tlBaseURL != "https://custom.tl/api" {
		t.Errorf("tlBaseURL = %q, want %q", cfg.tlBaseURL, "https://custom.tl/api")
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 5, "this ..."},
		{"", 5, ""},
	}
	for _, tc := range tests {
		got := sanitize(tc.input, tc.maxLen)
		if got != tc.want {
			t.Errorf("sanitize(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
		}
	}
}

func buildTLLogResponse(t *testing.T, agentID, status string) *models.TLResponse {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	lh := sha256.Sum256([]byte("diagnose-test-leaf"))
	leafHex := hex.EncodeToString(lh[:])

	resp := &models.TLResponse{
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
				IdentityCertFingerprint: "SHA256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
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
		},
		MerkleProof: models.MerkleProof{
			LeafHash:  leafHex,
			RootHash:  leafHex,
			LeafIndex: 0,
			TreeSize:  1,
			Path:      []string{},
		},
	}

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

	return resp
}

func ptrVersion(v models.Version) *models.Version {
	return &v
}
