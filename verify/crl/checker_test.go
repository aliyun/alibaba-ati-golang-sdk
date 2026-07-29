package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewChecker_Default(t *testing.T) {
	c := NewChecker()
	if c == nil {
		t.Fatal("NewChecker() returned nil")
	}
	if c.fetcher == nil {
		t.Error("fetcher is nil")
	}
}

func TestNewChecker_WithFetcher(t *testing.T) {
	f := NewFetcher(WithMaxAge(1 * time.Hour))
	c := NewChecker(WithFetcher(f))
	if c.fetcher != f {
		t.Error("custom fetcher was not set")
	}
}

func TestChecker_Check_CDPSkipped(t *testing.T) {
	c := NewChecker()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	chain := []*x509.Certificate{leaf}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Skipped {
		t.Errorf("status = %v, want Skipped", result.Status)
	}
}

func TestChecker_Check_CDPFailed(t *testing.T) {
	c := NewChecker()
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		CRLDistributionPoints: []string{"ldap://not-http.example.com"},
	}
	chain := []*x509.Certificate{leaf}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Failed {
		t.Errorf("status = %v, want Failed", result.Status)
	}
}

func TestChecker_Check_IssuerNotFound(t *testing.T) {
	ca, caKey := generateCheckerTestCA(t)
	crlBytes := generateCheckerTestCRL(t, ca, caKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()))
	c := NewChecker(WithFetcher(f))

	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		CRLDistributionPoints: []string{server.URL},
	}
	// Chain without the issuer
	chain := []*x509.Certificate{leaf}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Failed {
		t.Errorf("status = %v, want Failed (issuer not found)", result.Status)
	}
	if result.Message != "issuing CA not found in chain" {
		t.Errorf("message = %q", result.Message)
	}
}

func TestChecker_Check_FetchFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()))
	c := NewChecker(WithFetcher(f))

	ca, caKey := generateCheckerTestCA(t)
	leaf := generateCheckerTestLeaf(t, ca, caKey, server.URL)
	chain := []*x509.Certificate{leaf, ca}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Failed {
		t.Errorf("status = %v, want Failed (fetch error)", result.Status)
	}
}

func TestChecker_Check_Passed(t *testing.T) {
	ca, caKey := generateCheckerTestCA(t)
	crlBytes := generateCheckerTestCRL(t, ca, caKey) // empty CRL

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()))
	c := NewChecker(WithFetcher(f))

	leaf := generateCheckerTestLeaf(t, ca, caKey, server.URL)
	chain := []*x509.Certificate{leaf, ca}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Passed {
		t.Errorf("status = %v, want Passed, message: %s", result.Status, result.Message)
	}
	if result.CDPURI != server.URL {
		t.Errorf("CDPURI = %q, want %q", result.CDPURI, server.URL)
	}
}

func TestChecker_Check_Revoked(t *testing.T) {
	ca, caKey := generateCheckerTestCA(t)
	revokedSerial := big.NewInt(42)
	crlBytes := generateCheckerTestCRLWithRevoked(t, ca, caKey, revokedSerial)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()))
	c := NewChecker(WithFetcher(f))

	leaf := generateCheckerTestLeafWithSerial(t, ca, caKey, server.URL, revokedSerial)
	chain := []*x509.Certificate{leaf, ca}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Revoked {
		t.Errorf("status = %v, want Revoked, message: %s", result.Status, result.Message)
	}
}

func TestChecker_Check_ValidationFailed_BadSignature(t *testing.T) {
	ca, caKey := generateCheckerTestCA(t)
	otherCA, otherKey := generateCheckerTestCA(t)
	// CRL signed by otherCA but chain uses ca as issuer
	crlBytes := generateCheckerTestCRL(t, otherCA, otherKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()))
	c := NewChecker(WithFetcher(f))

	leaf := generateCheckerTestLeaf(t, ca, caKey, server.URL)
	chain := []*x509.Certificate{leaf, ca}

	result := c.Check(context.Background(), leaf, chain)
	if result.Status != Failed {
		t.Errorf("status = %v, want Failed (bad signature)", result.Status)
	}
}

func generateCheckerTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Checker Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	return cert, key
}

func generateCheckerTestCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlBytes
}

func generateCheckerTestCRLWithRevoked(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revokedSerial *big.Int) []byte {
	t.Helper()
	template := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now().Add(-1 * time.Hour)},
		},
		Number:     big.NewInt(2),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlBytes
}

func generateCheckerTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cdpURL string) *x509.Certificate {
	t.Helper()
	return generateCheckerTestLeafWithSerial(t, ca, caKey, cdpURL, big.NewInt(100))
}

func generateCheckerTestLeafWithSerial(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cdpURL string, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CRLDistributionPoints: []string{cdpURL},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	return cert
}
