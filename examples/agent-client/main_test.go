package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/ati"
)

func TestParseClientFlagsFromArgs_Defaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := parseClientFlagsFromArgs(fs, []string{})

	if cfg.certFile != "client.crt" {
		t.Errorf("certFile = %q, want %q", cfg.certFile, "client.crt")
	}
	if cfg.keyFile != "client.key" {
		t.Errorf("keyFile = %q, want %q", cfg.keyFile, "client.key")
	}
	if cfg.serverURL != "https://dns-test.aliyuncs.com:8443/hello" {
		t.Errorf("serverURL = %q, want default", cfg.serverURL)
	}
	if cfg.trustLevel != "badge" {
		t.Errorf("trustLevel = %q, want %q", cfg.trustLevel, "badge")
	}
	if cfg.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want %v", cfg.timeout, 10*time.Second)
	}
}

func TestParseClientFlagsFromArgs_Custom(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := parseClientFlagsFromArgs(fs, []string{
		"-cert", "my.crt",
		"-key", "my.key",
		"-url", "https://example.com/api",
		"-trust", "dane",
		"-timeout", "5s",
	})

	if cfg.certFile != "my.crt" {
		t.Errorf("certFile = %q, want %q", cfg.certFile, "my.crt")
	}
	if cfg.keyFile != "my.key" {
		t.Errorf("keyFile = %q, want %q", cfg.keyFile, "my.key")
	}
	if cfg.serverURL != "https://example.com/api" {
		t.Errorf("serverURL = %q, want %q", cfg.serverURL, "https://example.com/api")
	}
	if cfg.trustLevel != "dane" {
		t.Errorf("trustLevel = %q, want %q", cfg.trustLevel, "dane")
	}
	if cfg.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want %v", cfg.timeout, 5*time.Second)
	}
}

func TestParseClientFlagsFromArgs_NilArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := parseClientFlagsFromArgs(fs, nil)
	if cfg.certFile != "client.crt" {
		t.Errorf("certFile = %q, want default", cfg.certFile)
	}
}

func TestBuildClientOptions_PKIOnly(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "pki_only",
		timeout:    5 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_Badge(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "badge",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_DANE(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "dane",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_PKI(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "pki",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_BadgeRequired(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "badge_required",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_DANEAndBadge(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "dane_and_badge",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestFormatCertStatus(t *testing.T) {
	expiresAt := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	status := ati.CertStatus{
		ExpiresAt:     expiresAt,
		DaysRemaining: 90,
		IsExpired:     false,
	}

	result := formatCertStatus(status)
	if !strings.Contains(result, "2026-12-31") {
		t.Errorf("expected date in output, got %q", result)
	}
	if !strings.Contains(result, "90 days") {
		t.Errorf("expected days in output, got %q", result)
	}
}

func TestFormatCertStatus_Expired(t *testing.T) {
	expiresAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	status := ati.CertStatus{
		ExpiresAt:     expiresAt,
		DaysRemaining: -100,
		IsExpired:     true,
	}

	result := formatCertStatus(status)
	if !strings.Contains(result, "2024-01-01") {
		t.Errorf("expected date in output, got %q", result)
	}
}

func TestFormatResponse(t *testing.T) {
	result := formatResponse("200 OK", []byte(`{"ok":true}`))
	if !strings.Contains(result, "200 OK") {
		t.Errorf("expected status in output, got %q", result)
	}
	if !strings.Contains(result, `{"ok":true}`) {
		t.Errorf("expected body in output, got %q", result)
	}
}

func TestFormatVerificationOutcome_Nil(t *testing.T) {
	result := formatVerificationOutcome(nil)
	if result != "" {
		t.Errorf("expected empty string for nil outcome, got %q", result)
	}
}

func TestFormatVerificationOutcome_Full(t *testing.T) {
	level := ati.BadgeRequired
	outcome := &ati.TrustOutcome{
		DNSDiscovered:  true,
		CAChainValid:   true,
		SANMatches:     true,
		BadgeVerified:  true,
		DANEVerified:   false,
		AchievedLevel:  ati.BadgeRequired,
		RequestedLevel: &level,
		PeerATIName:    "ati://agent.example.com/v1.0.0",
		AgentID:        "ag-123",
	}

	result := formatVerificationOutcome(outcome)
	if !strings.Contains(result, "DNS Discovered:  true") {
		t.Errorf("expected DNS Discovered in output, got %q", result)
	}
	if !strings.Contains(result, "Badge Verified:  true") {
		t.Errorf("expected Badge Verified in output, got %q", result)
	}
	if !strings.Contains(result, "Requested Level:") {
		t.Errorf("expected Requested Level in output, got %q", result)
	}
	if !strings.Contains(result, "Peer ATI Name:") {
		t.Errorf("expected Peer ATI Name in output, got %q", result)
	}
	if !strings.Contains(result, "Agent ID:") {
		t.Errorf("expected Agent ID in output, got %q", result)
	}
}

func TestFormatVerificationOutcome_Minimal(t *testing.T) {
	outcome := &ati.TrustOutcome{
		DNSDiscovered: false,
		AchievedLevel: ati.PKIOnly,
	}

	result := formatVerificationOutcome(outcome)
	if strings.Contains(result, "Requested Level:") {
		t.Errorf("should not have Requested Level when nil")
	}
	if strings.Contains(result, "Peer ATI Name:") {
		t.Errorf("should not have Peer ATI Name when empty")
	}
	if strings.Contains(result, "Agent ID:") {
		t.Errorf("should not have Agent ID when empty")
	}
}

func TestRunClient_InvalidCert(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "/nonexistent/cert.pem",
		keyFile:    "/nonexistent/key.pem",
		serverURL:  "https://example.com/test",
		trustLevel: "badge",
		timeout:    5 * time.Second,
	}

	err := runClient(cfg)
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
}

func TestRunClient_ExpiredCert(t *testing.T) {
	certFile, keyFile := generateTestClientCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	cfg := &clientConfig{
		certFile:   certFile,
		keyFile:    keyFile,
		serverURL:  "https://example.com/test",
		trustLevel: "pki_only",
		timeout:    1 * time.Second,
	}

	err := runClient(cfg)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunClient_RequestFails(t *testing.T) {
	certFile, keyFile := generateTestClientCert(t, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))
	cfg := &clientConfig{
		certFile:   certFile,
		keyFile:    keyFile,
		serverURL:  "https://192.0.2.1:443/test",
		trustLevel: "pki_only",
		timeout:    100 * time.Millisecond,
	}

	err := runClient(cfg)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildClientOptions_None(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "none",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func generateTestClientCert(t *testing.T, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	atiURI, _ := url.Parse("ati://v1.0.0.test.example.com")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"test.example.com"},
		URIs:         []*url.URL{atiURI},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)
	return
}
