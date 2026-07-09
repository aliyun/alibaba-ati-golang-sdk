package ati

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// setupClientTestCerts generates a CA + identity cert with ATI URI SAN + CA file for tests.
func setupClientTestCerts(t *testing.T, host, version string) (identityCertFile, identityKeyFile, caBundleFile string) {
	t.Helper()
	dir := t.TempDir()

	caCert, caKey, caCertPEM, _ := generateCA(t)
	certPEM, keyPEM := generateCertWithATIName(t, caCert, caKey, host, version, []string{host})

	identityCertFile = writeTempFile(t, dir, "identity-cert-*.pem", certPEM)
	identityKeyFile = writeTempFile(t, dir, "identity-key-*.pem", keyPEM)
	caBundleFile = writeTempFile(t, dir, "ca-bundle-*.pem", caCertPEM)

	return identityCertFile, identityKeyFile, caBundleFile
}

// discoveryMockForHost creates a mock DNS resolver with _ati discovery records for a host.
func discoveryMockForHost(host string) *verify.MockDNSResolver {
	return verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{ID: "ag-test", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})
}

// discoveryMockForServer creates a mock DNS resolver for a httptest.Server URL.
func discoveryMockForServer(t *testing.T, serverURL string) *verify.MockDNSResolver {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return discoveryMockForHost(u.Hostname())
}

func TestNewAgentClient_Success(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithClientTimeout(10*time.Second),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewAgentClient() returned nil")
	}
	if client.trustLevel == nil || *client.trustLevel != BadgeRequired {
		t.Errorf("trustLevel = %v, want BadgeRequired (default)", client.trustLevel)
	}
}

func TestNewAgentClient_WithDNSResolver(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	mockResolver := verify.NewMockDNSResolver()
	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewAgentClient() returned nil")
	}
}

func TestNewAgentClient_MissingCerts(t *testing.T) {
	_, err := NewAgentClient()
	if err == nil {
		t.Fatal("expected error for missing certs, got nil")
	}
	if want := "identity certificate and private key are required"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewAgentClient_NoCABundle_UsesSystemCA(t *testing.T) {
	bundle := setupTestCertBundle(t)

	_, err := NewAgentClient(
		WithIdentityCert(bundle.ClientCertF, bundle.ClientKeyF),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("expected no error without CA bundle (should use system CA), got: %v", err)
	}
}

func TestNewAgentClient_InvalidCertKeyPair(t *testing.T) {
	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "cert-*.pem", []byte("not a cert"))
	keyFile := writeTempFile(t, dir, "key-*.pem", []byte("not a key"))
	caFile := writeTempFile(t, dir, "ca-*.pem", []byte("not a ca"))

	_, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
	)
	if err == nil {
		t.Fatal("expected error for invalid cert/key pair, got nil")
	}
}

func TestNewAgentClient_NonexistentFiles(t *testing.T) {
	_, err := NewAgentClient(
		WithMTLSCerts("/nonexistent/cert.pem", "/nonexistent/key.pem", "", "/nonexistent/ca.pem"),
	)
	if err == nil {
		t.Fatal("expected error for nonexistent files, got nil")
	}
}

func TestNewAgentClient_CertWithoutATIName(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caCertPEM, _ := generateCA(t)

	// Generate a cert without ATI URI SAN
	certPEM, keyPEM := generateCertWithoutATIName(t, caCert, caKey, "plain.example.com")

	certFile := writeTempFile(t, dir, "cert-*.pem", certPEM)
	keyFile := writeTempFile(t, dir, "key-*.pem", keyPEM)
	caFile := writeTempFile(t, dir, "ca-*.pem", caCertPEM)

	_, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
	)
	if err == nil {
		t.Fatal("expected error for cert without ATI name, got nil")
	}
	if want := "ATI Name"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewAgentClient_InvalidCABundle(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _, _ := generateCA(t)
	certPEM, keyPEM := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1.0.0", []string{"agent.example.com"})

	certFile := writeTempFile(t, dir, "cert-*.pem", certPEM)
	keyFile := writeTempFile(t, dir, "key-*.pem", keyPEM)
	invalidCA := writeTempFile(t, dir, "ca-*.pem", []byte("not a valid PEM"))

	_, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", invalidCA),
	)
	if err == nil {
		t.Fatal("expected error for invalid CA bundle, got nil")
	}
	if want := "不包含有效的 PEM 证书"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewAgentClient_NonexistentCAFile(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _, _ := generateCA(t)
	certPEM, keyPEM := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1.0.0", []string{"agent.example.com"})

	certFile := writeTempFile(t, dir, "cert-*.pem", certPEM)
	keyFile := writeTempFile(t, dir, "key-*.pem", keyPEM)

	_, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", "/nonexistent/ca.pem"),
	)
	if err == nil {
		t.Fatal("expected error for nonexistent CA file, got nil")
	}
	if want := "无法读取 CA bundle"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewAgentClient_ExpiringCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caCertPEM, _ := generateCA(t)

	// Generate a cert that expires in 15 days (< 30 day warning threshold)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	atiURI, _ := url.Parse("ati://v1.0.0.expiring.example.com")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			CommonName: "expiring.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(15 * 24 * time.Hour), // 15 days
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{atiURI},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := writeTempFile(t, dir, "cert-*.pem", certPEM)
	keyFile := writeTempFile(t, dir, "key-*.pem", keyPEM)
	caFile := writeTempFile(t, dir, "ca-*.pem", caCertPEM)

	// Should succeed but log a warning (we can't check log output easily)
	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	status := client.CertStatus()
	if status.DaysRemaining > 30 {
		t.Errorf("DaysRemaining = %d, expected <= 30", status.DaysRemaining)
	}
	if status.IsExpired {
		t.Error("cert should not be expired yet")
	}
}

func TestCertStatus(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	status := client.CertStatus()
	if status.IsExpired {
		t.Error("cert should not be expired")
	}
	if status.DaysRemaining < 0 {
		t.Errorf("DaysRemaining = %d, expected >= 0", status.DaysRemaining)
	}
	if status.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}

func TestCertStatus_Expired(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caCertPEM, _ := generateCA(t)

	// Generate an already-expired cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	atiURI, _ := url.Parse("ati://v1.0.0.expired.example.com")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject: pkix.Name{
			CommonName: "expired.example.com",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour), // already expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{atiURI},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := writeTempFile(t, dir, "cert-*.pem", certPEM)
	keyFile := writeTempFile(t, dir, "key-*.pem", keyPEM)
	caFile := writeTempFile(t, dir, "ca-*.pem", caCertPEM)

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	status := client.CertStatus()
	if !status.IsExpired {
		t.Error("cert should be expired")
	}
	if status.DaysRemaining > 0 {
		t.Errorf("DaysRemaining = %d, expected <= 0 for expired cert", status.DaysRemaining)
	}
}

func TestAgentClient_Do_InvalidURL(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	ctx := context.Background()

	// Invalid URL
	_, err = client.Do(ctx, http.MethodGet, "://invalid", nil)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestAgentClient_Do_MissingHostname(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	ctx := context.Background()

	_, err = client.Do(ctx, http.MethodGet, "https:///path", nil)
	if err == nil {
		t.Fatal("expected error for missing hostname, got nil")
	}
	if want := "missing hostname"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestAgentClient_Do_NonHTTPS(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	ctx := context.Background()

	_, err = client.Do(ctx, http.MethodGet, "http://example.com/path", nil)
	if err == nil {
		t.Fatal("expected error for non-HTTPS, got nil")
	}
	if want := "mTLS requires HTTPS"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestAgentClient_Get(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(discoveryMockForServer(t, server.URL)),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestAgentClient_Post(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["message"] != "hello" {
			t.Errorf("body message = %q, want %q", body["message"], "hello")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(discoveryMockForServer(t, server.URL)),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()
	resp, err := client.Post(ctx, server.URL, map[string]string{"message": "hello"})
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want 201", resp.StatusCode)
	}
}

func TestAgentClient_Put(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(discoveryMockForServer(t, server.URL)),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()
	resp, err := client.Put(ctx, server.URL, map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want 204", resp.StatusCode)
	}
}

func TestAgentClient_Delete(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(discoveryMockForServer(t, server.URL)),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()
	resp, err := client.Delete(ctx, server.URL)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestAgentClient_Do_WithBody(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(discoveryMockForServer(t, server.URL)),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()

	// Body that cannot be marshaled
	_, err = client.Do(ctx, http.MethodPost, server.URL, make(chan int))
	if err == nil {
		t.Fatal("expected error for unmarshalable body, got nil")
	}
	if want := "failed to marshal request body"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestAgentClient_Prefetch_Success(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*verify.ATIRecord{
			{ID: "ag-123", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeCard, URL: "https://example.com"},
		})

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.Prefetch(ctx, "agent.example.com")
	if err != nil {
		t.Fatalf("Prefetch() error = %v", err)
	}
}

func TestAgentClient_Prefetch_NotFound(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	mockResolver := verify.NewMockDNSResolver() // no records configured

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.Prefetch(ctx, "unknown.example.com")
	if err == nil {
		t.Fatal("expected error for missing DNS record, got nil")
	}
	if want := "no _ati TXT record found"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestAgentClient_Prefetch_InvalidHost(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}

	ctx := context.Background()
	err = client.Prefetch(ctx, "")
	if err == nil {
		t.Fatal("expected error for invalid host, got nil")
	}
	if want := "invalid host"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestBronzeOutcome_IsVerified(t *testing.T) {
	tests := []struct {
		name    string
		outcome BronzeOutcome
		want    bool
	}{
		{
			name: "all checks pass",
			outcome: BronzeOutcome{
				DNSDiscovered: true,
				CAChainValid:  true,
				SANMatches:    true,
			},
			want: true,
		},
		{
			name: "DNS not discovered",
			outcome: BronzeOutcome{
				DNSDiscovered: false,
				CAChainValid:  true,
				SANMatches:    true,
			},
			want: false,
		},
		{
			name: "CA chain invalid",
			outcome: BronzeOutcome{
				DNSDiscovered: true,
				CAChainValid:  false,
				SANMatches:    true,
			},
			want: false,
		},
		{
			name: "SAN mismatch",
			outcome: BronzeOutcome{
				DNSDiscovered: true,
				CAChainValid:  true,
				SANMatches:    false,
			},
			want: false,
		},
		{
			name:    "all false",
			outcome: BronzeOutcome{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.outcome.IsVerified(); got != tt.want {
				t.Errorf("IsVerified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithMTLSCerts_Option(t *testing.T) {
	cfg := &agentClientConfig{}
	opt := WithMTLSCerts("id.pem", "key.pem", "server.pem", "ca.pem")
	if err := opt(cfg); err != nil {
		t.Fatalf("WithMTLSCerts() error = %v", err)
	}
	if cfg.identityCertFile != "id.pem" {
		t.Errorf("identityCertFile = %q, want %q", cfg.identityCertFile, "id.pem")
	}
	if cfg.privateKeyFile != "key.pem" {
		t.Errorf("privateKeyFile = %q, want %q", cfg.privateKeyFile, "key.pem")
	}
	if cfg.serverCertFile != "server.pem" {
		t.Errorf("serverCertFile = %q, want %q", cfg.serverCertFile, "server.pem")
	}
	if cfg.caBundleFile != "ca.pem" {
		t.Errorf("caBundleFile = %q, want %q", cfg.caBundleFile, "ca.pem")
	}
}

func TestWithTrustLevel_Option(t *testing.T) {
	cfg := &agentClientConfig{}
	opt := WithTrustLevel(Gold)
	if err := opt(cfg); err != nil {
		t.Fatalf("WithTrustLevel() error = %v", err)
	}
	if cfg.trustLevel == nil || *cfg.trustLevel != Gold {
		t.Errorf("trustLevel = %v, want Gold", cfg.trustLevel)
	}
}

func TestWithClientTimeout_Option(t *testing.T) {
	cfg := &agentClientConfig{}
	opt := WithClientTimeout(5 * time.Second)
	if err := opt(cfg); err != nil {
		t.Fatalf("WithClientTimeout() error = %v", err)
	}
	if cfg.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", cfg.timeout)
	}
}

func TestWithDNSResolver_Option(t *testing.T) {
	cfg := &agentClientConfig{}
	mock := verify.NewMockDNSResolver()
	opt := WithDNSResolver(mock)
	if err := opt(cfg); err != nil {
		t.Fatalf("WithDNSResolver() error = %v", err)
	}
	if cfg.dnsResolver == nil {
		t.Error("dnsResolver is nil")
	}
}

func TestNewAgentClient_WithServerCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caCertPEM, _ := generateCA(t)
	identityCertPEM, identityKeyPEM := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1.0.0", []string{"agent.example.com"})
	serverCertPEM, _ := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com"})

	identityFile := writeTempFile(t, dir, "id-cert-*.pem", identityCertPEM)
	keyFile := writeTempFile(t, dir, "id-key-*.pem", identityKeyPEM)
	serverFile := writeTempFile(t, dir, "server-cert-*.pem", serverCertPEM)
	caFile := writeTempFile(t, dir, "ca-*.pem", caCertPEM)

	// Server cert will fail LoadX509KeyPair with identity key (different key),
	// so it falls back to using the identity cert for server
	client, err := NewAgentClient(
		WithMTLSCerts(identityFile, keyFile, serverFile, caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewAgentClient() returned nil")
	}
}

func TestAgentClient_Do_DNSDiscoveryBlocking(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach server when DNS discovery fails")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(verify.NewMockDNSResolver()),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()
	_, err = client.Do(ctx, http.MethodGet, server.URL, nil)
	if err == nil {
		t.Fatal("expected error when DNS discovery fails, got nil")
	}
	if want := "PKI verification failed"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestAgentClient_Do_PKIOnly(t *testing.T) {
	certFile, keyFile, caFile := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithMTLSCerts(certFile, keyFile, "", caFile),
		WithDNSResolver(discoveryMockForServer(t, server.URL)),
		WithTrustLevel(TrustPKI),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	client.httpClient = server.Client()

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.VerificationOutcome == nil {
		t.Fatal("VerificationOutcome is nil")
	}
	if resp.VerificationOutcome.RequestedLevel == nil || *resp.VerificationOutcome.RequestedLevel != PKIOnly {
		t.Errorf("RequestedLevel = %v, want PKIOnly", resp.VerificationOutcome.RequestedLevel)
	}
	if !resp.VerificationOutcome.DNSDiscovered {
		t.Error("DNSDiscovered should be true")
	}
}

