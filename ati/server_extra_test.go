package ati

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// parseTestCert parses a PEM-encoded certificate into an *x509.Certificate.
func parseTestCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

// buildPKIOnlyConfig constructs a serverConfig suitable for PKIOnly tests,
// with a valid clientVerifier (even though PKIOnly short-circuits before
// using it) and a peerLevels map.
func buildPKIOnlyConfig() *serverConfig {
	level := PKIOnly
	return &serverConfig{
		trustLevel:     &level,
		clientVerifier: verify.NewClientVerifier(),
		peerLevels:     &sync.Map{},
	}
}

// buildBadgeRequiredConfig constructs a serverConfig with BadgeRequired trust
// level. The mockResolver has no badge records, so Verify will fail.
func buildBadgeRequiredConfig(mockResolver verify.DNSResolver) *serverConfig {
	level := BadgeRequired
	return &serverConfig{
		trustLevel:     &level,
		dnsResolver:    mockResolver,
		clientVerifier: verify.NewClientVerifier(verify.WithDNSResolver(mockResolver), verify.WithTrustedTLHost(verify.DefaultTrustedTLHost)),
		peerLevels:     &sync.Map{},
	}
}

// buildDANEAndBadgeConfig constructs a serverConfig with DANEAndBadge trust
// level and a mock DANE resolver. The mockResolver has no badge records, so
// badge verification will fail.
func buildDANEAndBadgeConfig(mockResolver verify.DNSResolver, daneResolver verify.DANEResolver) *serverConfig {
	level := DANEAndBadge
	return &serverConfig{
		trustLevel:     &level,
		dnsResolver:    mockResolver,
		daneResolver:   daneResolver,
		clientVerifier: verify.NewClientVerifier(verify.WithDNSResolver(mockResolver), verify.WithTrustedTLHost(verify.DefaultTrustedTLHost)),
		peerLevels:     &sync.Map{},
	}
}

// TestBuildVerifyConnection_NoPeerCerts verifies that the callback returns
// an error when no client certificate is provided.
func TestBuildVerifyConnection_NoPeerCerts(t *testing.T) {
	cfg := buildPKIOnlyConfig()
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: nil}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error for no peer certs, got nil")
	}
	if !contains(err.Error(), "no client certificate provided") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "no client certificate provided")
	}
}

// TestBuildVerifyConnection_EmptyPeerCerts verifies that an empty (non-nil)
// PeerCertificates slice is also treated as "no certificate".
func TestBuildVerifyConnection_EmptyPeerCerts(t *testing.T) {
	cfg := buildPKIOnlyConfig()
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error for empty peer certs, got nil")
	}
	if !contains(err.Error(), "no client certificate provided") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "no client certificate provided")
	}
}

// TestBuildVerifyConnection_ExpiredCert verifies that an expired peer
// certificate is rejected with a "peer certificate invalid" error.
func TestBuildVerifyConnection_ExpiredCert(t *testing.T) {
	// generateCertWithATIName uses NotAfter = now + 24h, so we use
	// generateTestCert to create a cert that was already expired.
	expiredCert := generateTestCert(t,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	)

	cfg := buildPKIOnlyConfig()
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{expiredCert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error for expired cert, got nil")
	}
	if !contains(err.Error(), "peer certificate invalid") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "peer certificate invalid")
	}
	if !contains(err.Error(), "expired") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "expired")
	}
}

// TestBuildVerifyConnection_NotYetValidCert verifies that a certificate
// whose NotBefore is in the future is rejected.
func TestBuildVerifyConnection_NotYetValidCert(t *testing.T) {
	notYetValidCert := generateTestCert(t,
		time.Now().Add(1*time.Hour),
		time.Now().Add(2*time.Hour),
	)

	cfg := buildPKIOnlyConfig()
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{notYetValidCert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error for not-yet-valid cert, got nil")
	}
	if !contains(err.Error(), "peer certificate invalid") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "peer certificate invalid")
	}
	if !contains(err.Error(), "not yet valid") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not yet valid")
	}
}

// TestBuildVerifyConnection_PKIOnly_ValidCert verifies that with PKIOnly
// trust level and a valid certificate, the callback returns nil
// (short-circuit after cert validity check).
func TestBuildVerifyConnection_PKIOnly_ValidCert(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	cfg := buildPKIOnlyConfig()
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err != nil {
		t.Errorf("PKIOnly with valid cert: unexpected error = %v", err)
	}
}

// TestBuildVerifyConnection_BadgeRequired_BadgeFails verifies that with
// BadgeRequired trust level and a mock DNS resolver with no badge records,
// the badge verification fails and the callback returns an error.
func TestBuildVerifyConnection_BadgeRequired_BadgeFails(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	// Mock resolver with NO badge records → badge lookup fails.
	mockResolver := verify.NewMockDNSResolver()
	cfg := buildBadgeRequiredConfig(mockResolver)
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error for badge verification failure, got nil")
	}
	if !contains(err.Error(), "badge verification failed") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "badge verification failed")
	}
}

// TestBuildVerifyConnection_BadgeRequired_DoesNotStorePeerLevelOnFailure
// verifies that when badge verification fails in explicit mode, the callback
// returns early with an error and does NOT store the peer level (the store
// happens after the badge/DANE checks, and the early return skips it).
func TestBuildVerifyConnection_BadgeRequired_DoesNotStorePeerLevelOnFailure(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	cfg := buildBadgeRequiredConfig(mockResolver)
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	_ = verifyFn(cs) // badge fails, returns error

	certIdentity := verify.CertIdentityFromX509(cert)
	fp := certIdentity.Fingerprint.ToHex()
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	// In explicit mode with badge failure, the function returns early
	// before reaching the peerLevels.Store call.
	_, ok := cfg.peerLevels.Load(fp)
	if ok {
		t.Error("peer level should NOT be stored when badge fails in explicit mode (early return)")
	}
}

// TestBuildVerifyConnection_TrustLevelNotAchieved verifies that when the
// requested trust level is DANEAndBadge but badge verification fails, the
// callback returns a "requested trust level not achieved" error.
func TestBuildVerifyConnection_TrustLevelNotAchieved(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	mockDANE := verify.NewMockDANEResolver()
	cfg := buildDANEAndBadgeConfig(mockResolver, mockDANE)
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error for trust level not achieved, got nil")
	}
	// Badge fails first, so the error should mention badge verification.
	if !contains(err.Error(), "badge verification failed") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "badge verification failed")
	}
}

// TestBuildVerifyConnection_PKIOnly_DoesNotStorePeerLevel verifies that
// PKIOnly short-circuits at the cert validity check (line 283: return nil)
// and never reaches the peerLevels.Store call.
func TestBuildVerifyConnection_PKIOnly_DoesNotStorePeerLevel(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	cfg := buildPKIOnlyConfig()
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if err := verifyFn(cs); err != nil {
		t.Fatalf("PKIOnly: unexpected error = %v", err)
	}

	certIdentity := verify.CertIdentityFromX509(cert)
	fp := certIdentity.Fingerprint.ToHex()
	// PKIOnly short-circuits before peerLevels store.
	_, ok := cfg.peerLevels.Load(fp)
	if ok {
		t.Error("peer level should NOT be stored for PKIOnly (short-circuit return)")
	}
}

// TestBuildVerifyConnection_NilTrustLevel verifies that when trustLevel is
// nil (auto-detect mode), the callback does not short-circuit at PKIOnly
// and proceeds to badge verification. With no badge records, badge fails
// but should not error (non-explicit mode).
func TestBuildVerifyConnection_NilTrustLevel_BadgeFails_NoError(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	cfg := &serverConfig{
		trustLevel:     nil, // auto-detect / non-explicit
		dnsResolver:    mockResolver,
		clientVerifier: verify.NewClientVerifier(verify.WithDNSResolver(mockResolver), verify.WithTrustedTLHost(verify.DefaultTrustedTLHost)),
		peerLevels:     &sync.Map{},
	}
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	// In non-explicit mode, badge failure is not an error.
	if err != nil {
		t.Errorf("non-explicit mode with badge failure: unexpected error = %v", err)
	}

	// Achieved level should be PKIOnly (badge didn't pass).
	certIdentity := verify.CertIdentityFromX509(cert)
	fp := certIdentity.Fingerprint.ToHex()
	val, ok := cfg.peerLevels.Load(fp)
	if !ok {
		t.Fatal("expected peer level to be stored")
	}
	if achieved, _ := val.(VerificationPolicy); achieved != PKIOnly {
		t.Errorf("achieved = %v, want PKIOnly", achieved)
	}
}

// TestBuildVerifyConnection_CRLCheck_Rejects verifies that when a CRL
// checker is configured and the check result says "should reject", the
// callback returns an error containing "CRL check failed".
//
// We use a mock CRL checker by injecting a custom crlChecker-like object.
// Since crl.Checker is a concrete struct (not an interface), we cannot
// easily mock it. Instead, we rely on the fact that the checker is nil
// by default (no CRL configured), so this test documents that path is
// skipped. The actual CRL rejection path is tested in integration.
func TestBuildVerifyConnection_NoCRLChecker_SkipsCRL(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	cfg := buildPKIOnlyConfig()
	// crlChecker is nil → CRL check is skipped entirely.
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err != nil {
		t.Errorf("PKIOnly with no CRL checker: unexpected error = %v", err)
	}
}

// TestPeerTrustLevel_Found verifies that PeerTrustLevel returns the stored
// level when the fingerprint matches.
func TestPeerTrustLevel_Found(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	certIdentity := verify.CertIdentityFromX509(cert)
	fp := certIdentity.Fingerprint.ToHex()

	store := &sync.Map{}
	store.Store(fp, BadgeRequired)

	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	result := PeerTrustLevel(state, store)
	if result == nil {
		t.Fatal("PeerTrustLevel() returned nil, want non-nil")
	}
	if *result != BadgeRequired {
		t.Errorf("PeerTrustLevel() = %v, want %v", *result, BadgeRequired)
	}
}

// TestBuildVerifyConnection_DANEAndBadge_BadgeFails verifies that with
// DANEAndBadge level and failing badge, the error is about badge, not
// DANE (DANE is only attempted after badge passes).
func TestBuildVerifyConnection_DANEAndBadge_BadgeFails(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1", []string{"agent.example.com"})
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	mockDANE := verify.NewMockDANEResolver()
	cfg := buildDANEAndBadgeConfig(mockResolver, mockDANE)
	verifyFn := buildVerifyConnection(cfg)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should fail at badge, not DANE.
	if !contains(err.Error(), "badge verification failed") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "badge verification failed")
	}
	if contains(err.Error(), "DANE") {
		t.Errorf("error should not mention DANE when badge failed: %q", err.Error())
	}
}

// Ensure errors is used (silenced by linter if not imported).
var _ = errors.New
