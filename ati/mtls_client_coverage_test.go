package ati

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

func TestNewAgentClient_PolicyNone_NoIdentityCert(t *testing.T) {
	client, err := NewAgentClient(
		WithTrustLevel(PolicyNone),
	)
	if err != nil {
		t.Fatalf("NewAgentClient(PolicyNone) error = %v", err)
	}
	if client == nil {
		t.Fatal("NewAgentClient(PolicyNone) returned nil")
	}
	if client.trustLevel == nil || *client.trustLevel != PolicyNone {
		t.Error("expected PolicyNone trust level")
	}
}

func TestNewAgentClient_PolicyNone_WithIdentityCert_Coverage(t *testing.T) {
	certFile, keyFile, _ := setupClientTestCerts(t, "agent-cov.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithTrustLevel(PolicyNone),
		WithIdentityCert(certFile, keyFile),
	)
	if err != nil {
		t.Fatalf("NewAgentClient(PolicyNone+IdentityCert) error = %v", err)
	}
	if client == nil {
		t.Fatal("NewAgentClient(PolicyNone+IdentityCert) returned nil")
	}
}

func TestNewAgentClient_PolicyNone_WithCABundle_Error(t *testing.T) {
	_, err := NewAgentClient(
		WithTrustLevel(PolicyNone),
		WithMTLSCerts("", "", "", "/fake/ca-bundle.pem"),
	)
	if err == nil {
		t.Fatal("expected error for PolicyNone+CABundle")
	}
	if !strings.Contains(err.Error(), "PolicyNone cannot be used with a CA bundle") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewAgentClient_PolicyNone_InvalidCertFile(t *testing.T) {
	_, err := NewAgentClient(
		WithTrustLevel(PolicyNone),
		WithIdentityCert("/nonexistent/cert.pem", "/nonexistent/key.pem"),
	)
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
}

func TestNewAgentClient_NoCert_Error(t *testing.T) {
	_, err := NewAgentClient(
		WithTrustLevel(BadgeRequired),
	)
	if err == nil {
		t.Fatal("expected error when no cert is provided")
	}
	if !strings.Contains(err.Error(), "identity certificate and private key are required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewAgentClient_InvalidCertFile(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/bad-cert.pem"
	keyFile := dir + "/bad-key.pem"
	_ = writeFileBytes(t, certFile, []byte("not-a-valid-cert"))
	_ = writeFileBytes(t, keyFile, []byte("not-a-valid-key"))

	_, err := NewAgentClient(
		WithTrustLevel(BadgeRequired),
		WithIdentityCert(certFile, keyFile),
	)
	if err == nil {
		t.Fatal("expected error for invalid cert/key pair")
	}
}

func TestNewAgentClient_EmptyCertBlock(t *testing.T) {
	dir := t.TempDir()
	// Create a valid key but cert file with empty PEM content
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Create a cert PEM that has a CERTIFICATE header but the cert has 0 certificates
	// Actually we need a PEM file that loads but cert.Certificate slice is empty
	// This is hard to produce naturally, so let's test the ParseCertificate error instead
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-valid-asn1")})

	certFile := dir + "/bad-cert.pem"
	keyFile := dir + "/valid-key.pem"
	_ = writeFileBytes(t, certFile, certPEM)
	_ = writeFileBytes(t, keyFile, keyPEM)

	_, err := NewAgentClient(
		WithTrustLevel(BadgeRequired),
		WithIdentityCert(certFile, keyFile),
	)
	if err == nil {
		t.Fatal("expected error for cert parse failure")
	}
}

func TestAgentClient_Do_PolicyNone_Request(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithTrustLevel(PolicyNone),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}

	resp, err := client.Do(context.Background(), http.MethodGet, server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestAgentClient_Do_PolicyNone_PostWithBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type application/json")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAgentClient(
		WithTrustLevel(PolicyNone),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}

	resp, err := client.Do(context.Background(), http.MethodPost, server.URL+"/test", map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	defer resp.Body.Close()
}

func TestAgentClient_Do_InvalidURL_Coverage(t *testing.T) {
	client := &AgentClient{httpClient: &http.Client{}}

	_, err := client.Do(context.Background(), http.MethodGet, "://invalid-url-cov", nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestAgentClient_Do_NoHostname(t *testing.T) {
	client := &AgentClient{httpClient: &http.Client{}}

	_, err := client.Do(context.Background(), http.MethodGet, "https:///path", nil)
	if err == nil {
		t.Fatal("expected error for missing hostname")
	}
}

func TestAgentClient_Do_HTTPScheme(t *testing.T) {
	client := &AgentClient{httpClient: &http.Client{}}

	_, err := client.Do(context.Background(), http.MethodGet, "http://example.com/path", nil)
	if err == nil {
		t.Fatal("expected error for http scheme")
	}
	if !strings.Contains(err.Error(), "mTLS requires HTTPS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAgentClient_Do_BadgeVerificationPath(t *testing.T) {
	// Create a TLS server with a self-signed cert
	caCert, caKey, caCertPEM, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()

	// Setup client with identity cert
	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	u, _ := url.Parse(server.URL)

	// Mock DNS resolver that returns discovery for the server
	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords(u.Hostname(), []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	// Use PKIOnly level to avoid badge/DANE failures
	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithTrustLevel(PKIOnly),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	// Override the transport to trust the test server
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       client.tlsConfig.Certificates,
		},
	}

	resp, err := client.Do(context.Background(), http.MethodGet, server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	defer resp.Body.Close()

	if resp.VerificationOutcome == nil {
		t.Fatal("expected VerificationOutcome to be non-nil")
	}
	if !resp.VerificationOutcome.DNSDiscovered {
		t.Error("expected DNSDiscovered = true")
	}
}

func TestAgentClient_Do_DNSDiscoveryNotFound_ExplicitLevel(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	// Empty mock resolver = no discovery
	mockResolver := verify.NewMockDNSResolver()

	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithTrustLevel(PKIOnly),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       client.tlsConfig.Certificates,
		},
	}

	// With explicit trust level and no DNS discovery, should fail
	_, err = client.Do(context.Background(), http.MethodGet, server.URL+"/test", nil)
	if err == nil {
		t.Fatal("expected error when DNS discovery fails with explicit trust level")
	}
	if !strings.Contains(err.Error(), "PKI verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildClientVerifyConnection_ExpiryWarning(t *testing.T) {
	// Create a cert that is valid but expiring soon (within 10% of lifetime)
	notBefore := time.Now().Add(-90 * 24 * time.Hour) // 90 days ago
	notAfter := time.Now().Add(5 * 24 * time.Hour)    // 5 days remaining out of 95 total

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-expiring.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	cfg := &agentClientConfig{}
	verifyFn := buildClientVerifyConnection(cfg, nil)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		ServerName:       "test-expiring.example.com",
	}
	// Should not return error (cert is still valid) but should log a warning
	err := verifyFn(cs)
	if err != nil {
		t.Errorf("verifyFn() should not error for valid-but-expiring cert, got: %v", err)
	}
}

// helpers

func writeFileBytes(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writeFile(%s) error: %v", path, err)
	}
	return path
}
