package ati

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

// testCertBundle holds PEM-encoded cert material for tests.
type testCertBundle struct {
	CACertPEM    []byte
	CAKeyPEM     []byte
	ServerCert   []byte
	ServerKey    []byte
	ClientCert   []byte
	ClientKey    []byte
	CACertFile   string
	ServerCertF  string
	ServerKeyF   string
	ClientCertF  string
	ClientKeyF   string
}

// generateCA creates a self-signed CA certificate and key.
func generateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatalf("failed to marshal CA key: %v", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	return caCert, caKey, caCertPEM, caKeyPEM
}

// generateCertWithATIName creates a certificate signed by the CA with an ati:// URI SAN.
func generateCertWithATIName(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, host string, version string, dnsNames []string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	atiURI, err := url.Parse("ati://" + version + "." + host)
	if err != nil {
		t.Fatalf("failed to parse ATI URI: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Agent"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              dnsNames,
		URIs:                  []*url.URL{atiURI},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// generateCertWithoutATIName creates a certificate without an ati:// URI SAN.
func generateCertWithoutATIName(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, host string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// writeTempFile creates a temp file with the given content and returns its path.
func writeTempFile(t *testing.T, dir, prefix string, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(dir, prefix)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// setupTestCertBundle generates a full set of test certs and writes them to temp files.
func setupTestCertBundle(t *testing.T) *testCertBundle {
	t.Helper()
	dir := t.TempDir()

	caCert, caKey, caCertPEM, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "localhost"})
	clientCertPEM, clientKeyPEM := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})

	bundle := &testCertBundle{
		CACertPEM:  caCertPEM,
		ServerCert: serverCertPEM,
		ServerKey:  serverKeyPEM,
		ClientCert: clientCertPEM,
		ClientKey:  clientKeyPEM,
	}

	bundle.CACertFile = writeTempFile(t, dir, "ca-cert-*.pem", caCertPEM)
	bundle.ServerCertF = writeTempFile(t, dir, "server-cert-*.pem", serverCertPEM)
	bundle.ServerKeyF = writeTempFile(t, dir, "server-key-*.pem", serverKeyPEM)
	bundle.ClientCertF = writeTempFile(t, dir, "client-cert-*.pem", clientCertPEM)
	bundle.ClientKeyF = writeTempFile(t, dir, "client-key-*.pem", clientKeyPEM)

	return bundle
}

func TestNewServerTLSConfig_Success(t *testing.T) {
	t.Setenv("ATI_AK", "test-ak")
	t.Setenv("ATI_SK", "test-sk")
	bundle := setupTestCertBundle(t)

	tlsConfig, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA(bundle.CACertFile),
		WithClientVerifier(Silver),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("NewServerTLSConfig() returned nil config")
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsConfig.ClientAuth)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", tlsConfig.MinVersion)
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(tlsConfig.Certificates))
	}
	if tlsConfig.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
}

func TestNewServerTLSConfig_MissingServerCert(t *testing.T) {
	bundle := setupTestCertBundle(t)

	_, err := NewServerTLSConfig(
		WithClientCA(bundle.CACertFile),
	)
	if err == nil {
		t.Fatal("expected error for missing server cert, got nil")
	}
	if want := "server certificate and private key are required"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewServerTLSConfig_NoCABundle_AcceptsSelfSignedClients(t *testing.T) {
	bundle := setupTestCertBundle(t)

	// With a trust level set but no CA bundle, self-signed client certs are
	// accepted (RequireAnyClientCert); trust is established via Badge/TLog.
	tlsConfig, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientVerifier(PKIOnly),
	)
	if err != nil {
		t.Fatalf("expected no error without CA bundle, got: %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", tlsConfig.ClientAuth)
	}
	if tlsConfig.VerifyConnection == nil {
		t.Error("VerifyConnection should be set when a trust level is configured")
	}
}

func TestNewServerTLSConfig_NoTrustLevel_PlainConnection(t *testing.T) {
	bundle := setupTestCertBundle(t)

	// No WithClientVerifier and no WithClientCA → no client verification at all.
	tlsConfig, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
	)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tlsConfig.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tlsConfig.ClientAuth)
	}
	if tlsConfig.VerifyConnection != nil {
		t.Error("VerifyConnection should be nil when no trust level is configured")
	}
}

func TestNewServerTLSConfig_CABundleOnly_ImpliesPKI(t *testing.T) {
	bundle := setupTestCertBundle(t)

	// A private root cert (CA bundle) implies PKI verification even without
	// an explicit WithClientVerifier.
	tlsConfig, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA(bundle.CACertFile),
	)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsConfig.ClientAuth)
	}
	if tlsConfig.VerifyConnection == nil {
		t.Error("VerifyConnection should be set when a CA bundle is provided")
	}
}

func TestNewServerTLSConfig_InvalidServerCert(t *testing.T) {
	dir := t.TempDir()
	bundle := setupTestCertBundle(t)

	invalidCert := writeTempFile(t, dir, "invalid-*.pem", []byte("not a certificate"))

	_, err := NewServerTLSConfig(
		WithServerCert(invalidCert, bundle.ServerKeyF),
		WithClientCA(bundle.CACertFile),
	)
	if err == nil {
		t.Fatal("expected error for invalid server cert, got nil")
	}
}

func TestNewServerTLSConfig_InvalidCABundle(t *testing.T) {
	bundle := setupTestCertBundle(t)
	dir := t.TempDir()
	invalidCA := writeTempFile(t, dir, "invalid-ca-*.pem", []byte("not a PEM cert"))

	_, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA(invalidCA),
	)
	if err == nil {
		t.Fatal("expected error for invalid CA bundle, got nil")
	}
	if want := "不包含有效的 PEM 证书"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewServerTLSConfig_NonexistentCAFile(t *testing.T) {
	bundle := setupTestCertBundle(t)

	_, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA("/nonexistent/ca.pem"),
	)
	if err == nil {
		t.Fatal("expected error for nonexistent CA file, got nil")
	}
	if want := "无法读取 CA bundle"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestNewServerTLSConfig_NonexistentCertFile(t *testing.T) {
	bundle := setupTestCertBundle(t)

	_, err := NewServerTLSConfig(
		WithServerCert("/nonexistent/cert.pem", "/nonexistent/key.pem"),
		WithClientCA(bundle.CACertFile),
	)
	if err == nil {
		t.Fatal("expected error for nonexistent cert file, got nil")
	}
}

func TestNewServerTLSConfig_MismatchedCertAndKey(t *testing.T) {
	bundle := setupTestCertBundle(t)

	// Use server cert with client key (mismatch)
	_, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ClientKeyF),
		WithClientCA(bundle.CACertFile),
	)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key, got nil")
	}
}

func TestPeerATIName_Success(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "agent.example.com", "v1.0.0", []string{"agent.example.com"})

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	name, err := PeerATIName(state)
	if err != nil {
		t.Fatalf("PeerATIName() error = %v", err)
	}
	if name == nil {
		t.Fatal("PeerATIName() returned nil")
	}
	if name.Host != "agent.example.com" {
		t.Errorf("Host = %q, want %q", name.Host, "agent.example.com")
	}
	if name.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", name.Version, "v1.0.0")
	}
	if name.Raw != "ati://v1.0.0.agent.example.com" {
		t.Errorf("Raw = %q, want %q", name.Raw, "ati://v1.0.0.agent.example.com")
	}
}

func TestPeerATIName_NilState(t *testing.T) {
	_, err := PeerATIName(nil)
	if err == nil {
		t.Fatal("expected error for nil state, got nil")
	}
	if want := "no TLS connection state"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestPeerATIName_NoPeerCerts(t *testing.T) {
	state := &tls.ConnectionState{
		PeerCertificates: nil,
	}

	_, err := PeerATIName(state)
	if err == nil {
		t.Fatal("expected error for no peer certs, got nil")
	}
	if want := "no peer certificates"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestPeerATIName_NoATIURISAN(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithoutATIName(t, caCert, caKey, "agent.example.com")

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	_, err = PeerATIName(state)
	if err == nil {
		t.Fatal("expected error for cert without ATI URI, got nil")
	}
	if want := "no ati:// URI SAN found"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestPeerATIName_InvalidATIURI(t *testing.T) {
	// Create a cert with a malformed ati:// URI (missing parts)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// URI with ati:// prefix but invalid format (no version)
	badURI, _ := url.Parse("ati://invalidformat")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		URIs:                  []*url.URL{badURI},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	// Should return error because even though ati:// prefix exists,
	// ParseATIName will fail due to bad format
	_, err = PeerATIName(state)
	if err == nil {
		t.Fatal("expected error for invalid ATI URI, got nil")
	}
	if want := "no ati:// URI SAN found"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestServerTLSConfig_IntegrationMTLS(t *testing.T) {
	bundle := setupTestCertBundle(t)

	serverTLS, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA(bundle.CACertFile),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}

	// Start a TLS listener
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer ln.Close()

	// Set up client TLS config
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(bundle.CACertPEM)

	clientCert, err := tls.X509KeyPair(bundle.ClientCert, bundle.ClientKey)
	if err != nil {
		t.Fatalf("failed to load client cert: %v", err)
	}

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "server.example.com",
	}

	// Accept connections in a goroutine
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			done <- handshakeErr
			return
		}

		// Verify we can extract the ATI name from the client cert
		state := tlsConn.ConnectionState()
		name, nameErr := PeerATIName(&state)
		if nameErr != nil {
			done <- nameErr
			return
		}
		if name.Host != "client.example.com" {
			done <- fmt.Errorf("expected host client.example.com, got %s", name.Host)
			return
		}
		done <- nil
	}()

	// Connect client
	addr := ln.Addr().(*net.TCPAddr)
	conn, err := tls.Dial("tcp", addr.String(), clientTLS)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	conn.Close()

	// Wait for server to finish
	if serverErr := <-done; serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}
}

func TestWithServerCert_Option(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithServerCert("cert.pem", "key.pem")
	if err := opt(cfg); err != nil {
		t.Fatalf("WithServerCert() error = %v", err)
	}
	if cfg.serverCertFile != "cert.pem" {
		t.Errorf("serverCertFile = %q, want %q", cfg.serverCertFile, "cert.pem")
	}
	if cfg.privateKeyFile != "key.pem" {
		t.Errorf("privateKeyFile = %q, want %q", cfg.privateKeyFile, "key.pem")
	}
}

func TestWithClientCA_Option(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithClientCA("ca.pem")
	if err := opt(cfg); err != nil {
		t.Fatalf("WithClientCA() error = %v", err)
	}
	if cfg.caBundleFile != "ca.pem" {
		t.Errorf("caBundleFile = %q, want %q", cfg.caBundleFile, "ca.pem")
	}
}

func TestWithClientVerifier_Option(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithClientVerifier(Gold)
	if err := opt(cfg); err != nil {
		t.Fatalf("WithClientVerifier() error = %v", err)
	}
	if cfg.trustLevel == nil || *cfg.trustLevel != Gold {
		t.Errorf("trustLevel = %v, want Gold", cfg.trustLevel)
	}
}

func TestServerTLSConfig_RejectsClientWithoutATIName(t *testing.T) {
	t.Setenv("ATI_AK", "test-ak")
	t.Setenv("ATI_SK", "test-sk")
	bundle := setupTestCertBundle(t)

	serverTLS, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA(bundle.CACertFile),
		WithClientVerifier(TrustBadge),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}

	// Generate a client cert WITHOUT ATI URI SAN
	caCert, caKey, _, _ := generateCA(t)
	_ = caCert
	_ = caKey
	// Use the existing CA so the chain validates, but cert has no ati:// URI
	block, _ := pem.Decode(bundle.CACertPEM)
	caCertParsed, _ := x509.ParseCertificate(block.Bytes)

	// We need the CA key to sign the client cert. setupTestCertBundle doesn't
	// expose caKey, so generate a new bundle where we control the CA.
	ca2Cert, ca2Key, ca2CertPEM, _ := generateCA(t)
	noATICert, noATIKey := generateCertWithoutATIName(t, ca2Cert, ca2Key, "noncompliant.example.com")

	// Set up server config with the new CA
	dir := t.TempDir()
	ca2File := writeTempFile(t, dir, "ca2-*.pem", ca2CertPEM)
	serverCert, serverKey := generateCertWithATIName(t, ca2Cert, ca2Key, "server.example.com", "v1.0.0", []string{"server.example.com", "localhost"})
	sCertFile := writeTempFile(t, dir, "scert-*.pem", serverCert)
	sKeyFile := writeTempFile(t, dir, "skey-*.pem", serverKey)

	serverTLS, err = NewServerTLSConfig(
		WithServerCert(sCertFile, sKeyFile),
		WithClientCA(ca2File),
		WithClientVerifier(TrustBadge),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer ln.Close()

	_ = caCertParsed

	// Server accepts in goroutine
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		done <- tlsConn.Handshake()
	}()

	// Client connects with cert that has no ATI URI SAN
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca2CertPEM)

	clientCert, err := tls.X509KeyPair(noATICert, noATIKey)
	if err != nil {
		t.Fatalf("failed to load client cert: %v", err)
	}

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "server.example.com",
	}

	addr := ln.Addr().(*net.TCPAddr)
	conn, err := tls.Dial("tcp", addr.String(), clientTLS)
	if err == nil {
		conn.Close()
	}

	// Server should see a handshake error
	serverErr := <-done
	if serverErr == nil {
		t.Fatal("expected server handshake to fail for client cert without ATI URI SAN")
	}
}

func TestNewServerTLSConfig_HasVerifyConnection(t *testing.T) {
	t.Setenv("ATI_AK", "test-ak")
	t.Setenv("ATI_SK", "test-sk")
	bundle := setupTestCertBundle(t)

	tlsConfig, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, bundle.ServerKeyF),
		WithClientCA(bundle.CACertFile),
		WithClientVerifier(TrustBadge),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if tlsConfig.VerifyConnection == nil {
		t.Error("VerifyConnection callback should be set")
	}
}

func TestNewServerTLSConfig_EmptyKeyFile(t *testing.T) {
	bundle := setupTestCertBundle(t)

	_, err := NewServerTLSConfig(
		WithServerCert(bundle.ServerCertF, ""),
		WithClientCA(bundle.CACertFile),
	)
	if err == nil {
		t.Fatal("expected error for empty key file")
	}
}

// contains is a helper for checking substring in error messages.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

