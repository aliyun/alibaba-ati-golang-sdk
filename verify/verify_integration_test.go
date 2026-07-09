package verify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// Test the full AnsVerifier facade
func TestAnsVerifier_VerifyServer_InvalidFqdn(t *testing.T) {
	v := NewAnsVerifier()
	outcome := v.VerifyServer(context.Background(), "", nil)
	if outcome.Type != OutcomeCertError {
		t.Errorf("expected CertError for empty fqdn, got %v", outcome.Type)
	}
}

func TestAnsVerifier_Prefetch_InvalidFqdn(t *testing.T) {
	v := NewAnsVerifier()
	_, err := v.Prefetch(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty fqdn")
	}
}

func TestAnsVerifier_VerifyClient_NoCN(t *testing.T) {
	v := NewAnsVerifier()
	cert := &CertIdentity{
		CommonName:  nil,
		DNSSANs:     nil,
		Fingerprint: CertFingerprintFromBytes([32]byte{1, 2, 3}),
	}
	outcome := v.VerifyClient(context.Background(), cert)
	if outcome.Type != OutcomeCertError {
		t.Errorf("expected CertError for no CN, got %v", outcome.Type)
	}
}

func TestAnsVerifier_VerifyClient_NoURISAN(t *testing.T) {
	v := NewAnsVerifier()
	cn := "test.example.com"
	cert := &CertIdentity{
		CommonName:  &cn,
		DNSSANs:     []string{cn},
		URISANs:     nil,
		Fingerprint: CertFingerprintFromBytes([32]byte{1, 2, 3}),
	}
	outcome := v.VerifyClient(context.Background(), cert)
	if outcome.Type != OutcomeCertError {
		t.Errorf("expected CertError for no URI SAN, got %v", outcome.Type)
	}
}

func TestServerVerifier_FailClosed_DNSError(t *testing.T) {
	mockDNS := NewMockDNSResolver().
		WithError("test.example.com", errors.New("dns failure"))

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithFailurePolicy(FailClosed),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	outcome := v.Verify(context.Background(), fqdn, &CertIdentity{})
	if outcome.Type != OutcomeDNSError {
		t.Errorf("expected DNSError, got %v", outcome.Type)
	}
}

func TestServerVerifier_FailOpen_DNSError(t *testing.T) {
	mockDNS := NewMockDNSResolver().
		WithError("test.example.com", errors.New("dns failure"))

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithFailurePolicy(FailOpen),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	outcome := v.Verify(context.Background(), fqdn, &CertIdentity{})
	if outcome.Type != OutcomeFailOpen {
		t.Errorf("expected FailOpen outcome, got %v", outcome.Type)
	}
}

func TestServerVerifier_FailOpenWithCache_DNSError_NoCache(t *testing.T) {
	mockDNS := NewMockDNSResolver().
		WithError("test.example.com", errors.New("dns failure"))

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithFailurePolicy(FailOpenWithCache),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	outcome := v.Verify(context.Background(), fqdn, &CertIdentity{})
	// No cache configured, so falls back to error
	if outcome.Type != OutcomeDNSError {
		t.Errorf("expected DNSError (no cache), got %v", outcome.Type)
	}
}

func TestServerVerifier_NotATIAgent_NoRecords(t *testing.T) {
	mockDNS := NewMockDNSResolver() // No records for any FQDN

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithFailurePolicy(FailOpen), // Even with FailOpen, not-found is not retried
	)

	fqdn, _ := models.NewFqdn("noans.example.com")
	outcome := v.Verify(context.Background(), fqdn, &CertIdentity{})
	if outcome.Type != OutcomeNotATIAgent {
		t.Errorf("expected NotATIAgent, got %v", outcome.Type)
	}
}

func TestServerVerifier_TlogError(t *testing.T) {
	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithError("https://tlog.example.com/badge/123", errors.New("tlog error"))

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	outcome := v.Verify(context.Background(), fqdn, &CertIdentity{})
	if outcome.Type != OutcomeTlogError {
		t.Errorf("expected TlogError, got %v", outcome.Type)
	}
}

func TestServerVerifier_InvalidBadgeStatus(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusRevoked),
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	fp := CertFingerprintFromBytes([32]byte{})
	cert := CertIdentityFromFingerprintAndCN(fp, "test.example.com")
	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeInvalidStatus {
		t.Errorf("expected InvalidStatus, got %v", outcome.Type)
	}
}

func TestServerVerifier_SuccessfulVerification(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:0102030000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := CertIdentityFromFingerprintAndCN(fp, "test.example.com")
	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeVerified {
		t.Errorf("expected Verified, got %v", outcome.Type)
	}
}

func TestServerVerifier_CachedBadge(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:0102030000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	cache := NewBadgeCache(CacheConfig{MaxEntries: 100, DefaultTTL: 5 * time.Minute})
	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithCache(cache),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := CertIdentityFromFingerprintAndCN(fp, "test.example.com")

	// First call: fetches from DNS + TLog
	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeVerified {
		t.Fatalf("first call: expected Verified, got %v", outcome.Type)
	}

	// Second call: should use cache (we can verify it still works)
	outcome = v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeVerified {
		t.Fatalf("second call: expected Verified, got %v", outcome.Type)
	}
}

func TestServerVerifier_Prefetch_WithCache(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	cache := NewBadgeCache(DefaultCacheConfig())
	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithCache(cache),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := v.Prefetch(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil badge")
	}
}

func TestServerVerifier_Prefetch_Error(t *testing.T) {
	mockDNS := NewMockDNSResolver() // No records

	v := NewServerVerifier(WithDNSResolver(mockDNS))

	fqdn, _ := models.NewFqdn("noans.example.com")
	_, err := v.Prefetch(context.Background(), fqdn)
	if err == nil {
		t.Error("expected error for not-found agent")
	}
}

func TestServerVerifier_HostnameMismatch_BadgeHost(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
			AgentHost:   "other.example.com",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:0102030000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := CertIdentityFromFingerprintAndCN(fp, "test.example.com")
	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeHostnameMismatch {
		t.Errorf("expected HostnameMismatch, got %v", outcome.Type)
	}
}

func TestServerVerifier_FingerprintMismatch_BadgeCert(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := CertIdentityFromFingerprintAndCN(fp, "test.example.com")
	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeFingerprintMismatch {
		t.Errorf("expected FingerprintMismatch, got %v", outcome.Type)
	}
}

func TestServerVerifier_DeprecatedBadge(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusDeprecated),
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:0102030000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123"},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewServerVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := CertIdentityFromFingerprintAndCN(fp, "test.example.com")
	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome.Type != OutcomeVerified {
		t.Errorf("expected Verified (deprecated is valid), got %v", outcome.Type)
	}
	if len(outcome.Warnings) == 0 {
		t.Error("expected warnings for deprecated badge")
	}
}

func TestClientVerifier_SuccessfulVerification(t *testing.T) {
	version, _ := models.ParseVersion("v1.0.0")
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
			AgentName:   "ati://v1.0.0.test.example.com",
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "SHA256:0102030000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123", Version: &version},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewClientVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	cn := "test.example.com"
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := &CertIdentity{
		CommonName:  &cn,
		DNSSANs:     []string{cn},
		URISANs:     []string{"ati://v1.0.0.test.example.com"},
		Fingerprint: fp,
	}

	outcome := v.Verify(context.Background(), cert)
	if outcome.Type != OutcomeVerified {
		t.Errorf("expected Verified, got %v", outcome.Type)
	}
}

func TestClientVerifier_IdentityFingerprintMismatch(t *testing.T) {
	version, _ := models.ParseVersion("v1.0.0")
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			AgentStatus: string(models.TLStatusActive),
			AgentName:   "ati://v1.0.0.test.example.com",
			AgentHost:   "test.example.com",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}

	mockDNS := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{
			{URL: "https://tlog.example.com/badge/123", Version: &version},
		})
	mockTlog := NewMockTransparencyLogClient().
		WithTLResponse("https://tlog.example.com/badge/123", tlResp)

	v := NewClientVerifier(
		WithDNSResolver(mockDNS),
		WithTlogClient(mockTlog),
		WithoutURLValidation(),
	)

	cn := "test.example.com"
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := &CertIdentity{
		CommonName:  &cn,
		DNSSANs:     []string{cn},
		URISANs:     []string{"ati://v1.0.0.test.example.com"},
		Fingerprint: fp,
	}

	outcome := v.Verify(context.Background(), cert)
	if outcome.Type != OutcomeFingerprintMismatch {
		t.Errorf("expected FingerprintMismatch, got %v", outcome.Type)
	}
}

func TestClientVerifier_InvalidFqdn(t *testing.T) {
	v := NewClientVerifier()

	cn := "not a valid fqdn !!!"
	cert := &CertIdentity{
		CommonName: &cn,
		DNSSANs:    []string{cn},
		URISANs:    []string{"ati://v1.0.0." + cn},
	}

	outcome := v.Verify(context.Background(), cert)
	if outcome.Type != OutcomeCertError {
		t.Errorf("expected CertError for invalid fqdn, got %v", outcome.Type)
	}
}

func TestClientVerifier_DNSError(t *testing.T) {
	mockDNS := NewMockDNSResolver().
		WithError("test.example.com", errors.New("dns failure"))

	v := NewClientVerifier(
		WithDNSResolver(mockDNS),
		WithFailurePolicy(FailClosed),
	)

	cn := "test.example.com"
	fp := CertFingerprintFromBytes([32]byte{1, 2, 3})
	cert := &CertIdentity{
		CommonName:  &cn,
		DNSSANs:     []string{cn},
		URISANs:     []string{"ati://v1.0.0.test.example.com"},
		Fingerprint: fp,
	}

	outcome := v.Verify(context.Background(), cert)
	if outcome.Type != OutcomeDNSError {
		t.Errorf("expected DNSError, got %v", outcome.Type)
	}
}
