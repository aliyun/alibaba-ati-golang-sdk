package ati

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify/crl"
)

func TestNewServerTLSConfig_OptionError(t *testing.T) {
	badOpt := func(c *serverConfig) error {
		return &testError{msg: "option error"}
	}

	_, err := NewServerTLSConfig(badOpt)
	if err == nil {
		t.Fatal("expected error from bad option")
	}
	if !contains(err.Error(), "option error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewServerTLSConfig_DANEAutoCreate(t *testing.T) {
	certFile, keyFile, caFile := setupServerTestCerts(t, "server.example.com")

	cfg, err := NewServerTLSConfig(
		WithServerCert(certFile, keyFile),
		WithClientCA(caFile),
		WithClientVerifier(DANEAndBadge),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
}

func TestNewServerTLSConfig_CRLAutoEnable(t *testing.T) {
	certFile, keyFile, caFile := setupServerTestCerts(t, "server.example.com")

	cfg, err := NewServerTLSConfig(
		WithServerCert(certFile, keyFile),
		WithClientCA(caFile),
		WithClientVerifier(BadgeRequired),
		WithCRLCheck(),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
}

func TestNewServerTLSConfig_WithTLogClient(t *testing.T) {
	certFile, keyFile, caFile := setupServerTestCerts(t, "server.example.com")

	// Set tlogClient via a custom option since there's no public WithServerTLogClient
	mockTLog := verify.NewMockTransparencyLogClient()
	setTLog := func(c *serverConfig) error {
		c.tlogClient = mockTLog
		return nil
	}

	cfg, err := NewServerTLSConfig(
		WithServerCert(certFile, keyFile),
		WithClientCA(caFile),
		WithClientVerifier(BadgeRequired),
		setTLog,
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
}

func TestBuildVerifyConnection_CertExpiryWarning(t *testing.T) {
	notBefore := time.Now().Add(-90 * 24 * time.Hour)
	notAfter := time.Now().Add(3 * 24 * time.Hour)

	cert := generateTestCert(t, notBefore, notAfter)

	level := PKIOnly
	cfg := &serverConfig{
		trustLevel:     &level,
		clientVerifier: verify.NewClientVerifier(),
		peerLevels:     &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err != nil {
		t.Errorf("PKIOnly with valid cert should pass, got: %v", err)
	}
}

func TestBuildVerifyConnection_BadgeFail_Explicit(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	level := BadgeRequired
	cfg := &serverConfig{
		trustLevel:     &level,
		dnsResolver:    mockResolver,
		clientVerifier: verify.NewClientVerifier(verify.WithDNSResolver(mockResolver), verify.WithTrustedTLHost(verify.DefaultTrustedTLHost)),
		peerLevels:     &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error when badge verification fails in explicit mode")
	}
	if !contains(err.Error(), "badge verification failed") {
		t.Errorf("error = %q, want 'badge verification failed'", err.Error())
	}
}

func TestBuildVerifyConnection_DANE_NoATIName(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithoutATIName(t, caCert, caKey, "client.example.com")
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	level := DANEAndBadge
	cfg := &serverConfig{
		trustLevel:     &level,
		dnsResolver:    mockResolver,
		daneResolver:   verify.NewMockDANEResolver(),
		clientVerifier: verify.NewClientVerifier(verify.WithDNSResolver(mockResolver), verify.WithTrustedTLHost(verify.DefaultTrustedTLHost)),
		peerLevels:     &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error when DANEAndBadge required but badge fails")
	}
}

func TestBuildVerifyConnection_TrustLevelNotAchieved_Coverage(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	mockResolver := verify.NewMockDNSResolver()
	level := DANEAndBadge
	cfg := &serverConfig{
		trustLevel:     &level,
		dnsResolver:    mockResolver,
		daneResolver:   verify.NewMockDANEResolver(),
		clientVerifier: verify.NewClientVerifier(verify.WithDNSResolver(mockResolver), verify.WithTrustedTLHost(verify.DefaultTrustedTLHost)),
		peerLevels:     &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected error when badge verification fails with DANEAndBadge level")
	}
}

func TestBuildVerifyConnection_CRLPassed(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	level := PKIOnly
	// CRL checker with no CRL data = check passes (no CDP in cert)
	checker := crl.NewChecker(crl.WithFetcher(crl.NewFetcher()))
	cfg := &serverConfig{
		trustLevel:     &level,
		clientVerifier: verify.NewClientVerifier(),
		peerLevels:     &sync.Map{},
		crlChecker:     checker,
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err != nil {
		t.Errorf("PKIOnly with CRL (no CDP) should pass, got: %v", err)
	}
}

// helpers

func setupServerTestCerts(t *testing.T, host string) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey, caCertPEM, _ := generateCA(t)
	certPEM, keyPEM := generateCertWithATIName(t, caCert, caKey, host, "v1.0.0", []string{host})
	certFile = writeTempFile(t, dir, "server-cert-*.pem", certPEM)
	keyFile = writeTempFile(t, dir, "server-key-*.pem", keyPEM)
	caFile = writeTempFile(t, dir, "ca-bundle-*.pem", caCertPEM)
	return
}

type testError struct {
	msg string
}

func (e *testError) Error() string { return e.msg }

