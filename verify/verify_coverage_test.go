package verify

import (
	"context"
	"log/slog"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestRewriteTLHost_InvalidURL(t *testing.T) {
	cfg := &verifierConfig{
		trustedTLHost: DefaultTrustedTLHost,
	}
	log := configLogger(cfg)

	result := rewriteTLHost(cfg, "://invalid-url-no-scheme", log)
	if result != "://invalid-url-no-scheme" {
		t.Errorf("expected original URL returned on error, got %q", result)
	}
}

func TestRewriteTLHost_EmptyTrustedHost(t *testing.T) {
	cfg := &verifierConfig{
		trustedTLHost: "",
	}
	log := configLogger(cfg)

	result := rewriteTLHost(cfg, "https://original.example.com/path", log)
	if result != "https://original.example.com/path" {
		t.Errorf("expected original URL when trustedTLHost is empty, got %q", result)
	}
}

func TestRewriteTLHost_ValidRewrite(t *testing.T) {
	cfg := &verifierConfig{
		trustedTLHost: "my-trusted-host.example.com",
	}
	log := configLogger(cfg)

	result := rewriteTLHost(cfg, "https://original.example.com/api/badge/test", log)
	if result != "https://my-trusted-host.example.com/api/badge/test" {
		t.Errorf("expected rewritten URL, got %q", result)
	}
}

func TestServerVerifier_FetchTLResponse_NilRecord(t *testing.T) {
	mockResolver := NewMockDNSResolver().
		WithRecords("test.example.com", []ATIBadgeRecord{})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithTrustedTLHost(DefaultTrustedTLHost),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes([32]byte{1, 2, 3}),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if outcome.Type != OutcomeNotATIAgent {
		t.Errorf("expected OutcomeNotATIAgent, got %v", outcome.Type)
	}
}

func TestServerVerifier_Verify_DNSError(t *testing.T) {
	mockResolver := NewMockDNSResolver().
		WithError("test.example.com", &testVerifyError{msg: "DNS timeout"})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithTrustedTLHost(DefaultTrustedTLHost),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes([32]byte{1, 2, 3}),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if outcome.Type != OutcomeDNSError {
		t.Errorf("expected OutcomeDNSError, got %v", outcome.Type)
	}
}

func TestServerVerifier_CacheHit_Pass(t *testing.T) {
	fqdn, _ := models.NewFqdn("cached.example.com")
	fpBytes := [32]byte{0xaa, 0xbb, 0xcc}
	fpHex := "aabbcc0000000000000000000000000000000000000000000000000000000000"

	cache := NewBadgeCache(DefaultCacheConfig())
	cache.Insert(fqdn, &models.TLResponse{
		Status:        "success",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			AgentName:   "ati://v1.0.0.cached.example.com",
			AgentHost:   "cached.example.com",
			AgentStatus: "ACTIVE",
			Certificates: models.TLCertificates{
				ServerCertFingerprint: "SHA256:" + fpHex,
			},
		},
	})

	v := NewServerVerifier(
		WithDNSResolver(NewMockDNSResolver()),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithTrustedTLHost(DefaultTrustedTLHost),
		WithCache(cache),
	)

	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes(fpBytes),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if outcome.Type != OutcomeVerified {
		t.Errorf("expected OutcomeVerified from cache hit, got %v", outcome.Type)
	}
}

func TestServerVerifier_CacheHit_FingerprintMismatch_FallsThrough(t *testing.T) {
	fqdn, _ := models.NewFqdn("mismatch.example.com")

	cache := NewBadgeCache(DefaultCacheConfig())
	cache.Insert(fqdn, &models.TLResponse{
		Status:        "success",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			AgentName:   "ati://v1.0.0.mismatch.example.com",
			AgentHost:   "mismatch.example.com",
			AgentStatus: "ACTIVE",
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "SHA256:1111111111111111111111111111111111111111111111111111111111111111",
			},
		},
	})

	mockResolver := NewMockDNSResolver().
		WithRecords("mismatch.example.com", []ATIBadgeRecord{})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithTrustedTLHost(DefaultTrustedTLHost),
		WithCache(cache),
	)

	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes([32]byte{0x22, 0x33}),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	// After cache miss due to fingerprint mismatch, falls through to DNS lookup
	// and gets NotATIAgent because empty records
	if outcome.Type != OutcomeNotATIAgent {
		t.Errorf("expected OutcomeNotATIAgent after fallthrough, got %v", outcome.Type)
	}
}

func TestServerVerifier_Prefetch_DNSError(t *testing.T) {
	mockResolver := NewMockDNSResolver().
		WithError("fail.example.com", &testVerifyError{msg: "DNS failure"})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(NewMockTransparencyLogClient()),
	)

	fqdn, _ := models.NewFqdn("fail.example.com")
	_, err := v.Prefetch(context.Background(), fqdn)
	if err == nil {
		t.Fatal("expected error for DNS failure")
	}
}

func TestServerVerifier_Prefetch_Success_WithCache(t *testing.T) {
	fqdn, _ := models.NewFqdn("fresh.example.com")
	v100 := models.NewVersion(1, 0, 0)

	badgeURL := "https://tl.example.com/api/v1/badge"
	mockResolver := NewMockDNSResolver().
		WithRecords("fresh.example.com", []ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	tlResp := &models.TLResponse{
		Status:        "success",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			AgentHost: "fresh.example.com",
		},
	}
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(badgeURL, tlResp)

	cache := NewBadgeCache(DefaultCacheConfig())
	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(mockTLog),
		WithCache(cache),
	)

	resp, err := v.Prefetch(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Payload.AgentHost != "fresh.example.com" {
		t.Errorf("unexpected response: %v", resp)
	}

	// Verify it was cached
	cached, ok := cache.GetByFqdn(fqdn)
	if !ok {
		t.Error("expected response to be cached")
	}
	if cached.TLResponse.Payload.AgentHost != "fresh.example.com" {
		t.Error("cached response doesn't match")
	}
}

// Suppress unused import warning for slog
var _ = slog.Default

func TestServerVerifier_TLogError(t *testing.T) {
	v100 := models.NewVersion(1, 0, 0)
	badgeURL := "https://tl.atiagent.cn/api/v1/badge"
	mockResolver := NewMockDNSResolver().
		WithRecords("tlogerr.example.com", []ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	mockTLog := NewMockTransparencyLogClient().
		WithError(badgeURL, &testVerifyError{msg: "TLog unavailable"})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(mockTLog),
		WithTrustedTLHost(DefaultTrustedTLHost),
	)

	fqdn, _ := models.NewFqdn("tlogerr.example.com")
	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes([32]byte{1}),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if outcome.Type != OutcomeTlogError {
		t.Errorf("expected OutcomeTlogError, got %v", outcome.Type)
	}
}

func TestServerVerifier_InvalidAgentStatus(t *testing.T) {
	v100 := models.NewVersion(1, 0, 0)
	badgeURL := "https://tl.atiagent.cn/api/v1/badge"
	fpHex := "0102030000000000000000000000000000000000000000000000000000000000"

	mockResolver := NewMockDNSResolver().
		WithRecords("revoked.example.com", []ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	mockTLog := NewMockTransparencyLogClient().
		WithTLResponse(badgeURL, &models.TLResponse{
			Status:        "success",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentName:   "ati://v1.0.0.revoked.example.com",
				AgentHost:   "revoked.example.com",
				AgentStatus: "REVOKED",
				Certificates: models.TLCertificates{
					ServerCertFingerprint: "SHA256:" + fpHex,
				},
			},
		})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(mockTLog),
		WithTrustedTLHost(DefaultTrustedTLHost),
	)

	fqdn, _ := models.NewFqdn("revoked.example.com")
	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes([32]byte{1, 2, 3}),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	// REVOKED is not valid for connection → should return invalid status outcome
	if outcome.Type == OutcomeVerified {
		t.Error("did not expect OutcomeVerified for REVOKED agent")
	}
}

func TestServerVerifier_HostnameMismatch_AgentHostVsFqdn(t *testing.T) {
	v100 := models.NewVersion(1, 0, 0)
	badgeURL := "https://tl.atiagent.cn/api/v1/badge"
	fpHex := "0102030000000000000000000000000000000000000000000000000000000000"

	mockResolver := NewMockDNSResolver().
		WithRecords("actual.example.com", []ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	mockTLog := NewMockTransparencyLogClient().
		WithTLResponse(badgeURL, &models.TLResponse{
			Status:        "success",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentName:   "ati://v1.0.0.wrong.example.com",
				AgentHost:   "wrong.example.com",
				AgentStatus: "ACTIVE",
				Certificates: models.TLCertificates{
					ServerCertFingerprint: "SHA256:" + fpHex,
				},
			},
		})

	v := NewServerVerifier(
		WithDNSResolver(mockResolver),
		WithTlogClient(mockTLog),
		WithTrustedTLHost(DefaultTrustedTLHost),
	)

	fqdn, _ := models.NewFqdn("actual.example.com")
	cert := &CertIdentity{
		Fingerprint: CertFingerprintFromBytes([32]byte{1, 2, 3}),
	}

	outcome := v.Verify(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	// AgentHost doesn't match fqdn → hostname mismatch
	if outcome.Type == OutcomeVerified {
		t.Error("did not expect OutcomeVerified for hostname mismatch")
	}
}

func TestDANEVerifier_VerifyIdentity_Pass(t *testing.T) {
	fpBytes := [32]byte{0xde, 0xad}
	spkiHex := "dead000000000000000000000000000000000000000000000000000000000000"

	mockDANE := NewMockDANEResolver().
		WithIdentityTLSA("test.example.com", TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records: []TLSARecord{
				{Usage: 3, Selector: 1, MatchingType: 1, CertHash: spkiHex},
			},
		})

	verifier := NewDANEVerifier(mockDANE)
	fqdn, _ := models.NewFqdn("test.example.com")
	cert := &CertIdentity{
		SPKIFingerprint: CertFingerprintFromBytes(fpBytes),
	}

	outcome := verifier.VerifyIdentity(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if outcome.Type != DANEVerified {
		t.Errorf("expected DANEVerified, got %v", outcome.Type)
	}
}

func TestDANEVerifier_VerifyIdentity_Error(t *testing.T) {
	mockDANE := NewMockDANEResolver().
		WithIdentityError("fail.example.com", &testVerifyError{msg: "identity lookup failed"})

	verifier := NewDANEVerifier(mockDANE)
	fqdn, _ := models.NewFqdn("fail.example.com")
	cert := &CertIdentity{
		SPKIFingerprint: CertFingerprintFromBytes([32]byte{1}),
	}

	outcome := verifier.VerifyIdentity(context.Background(), fqdn, cert)
	if outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if outcome.Type != DANELookupError {
		t.Errorf("expected DANELookupError, got %v", outcome.Type)
	}
}

type testVerifyError struct {
	msg string
}

func (e *testVerifyError) Error() string { return e.msg }
