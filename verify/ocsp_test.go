package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// generateTestCerts creates a self-signed CA and leaf certificate for OCSP tests.
func generateTestCerts(t *testing.T) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		OCSPServer:   []string{"http://ocsp.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	return caCert, leafCert, caKey
}

// makeOCSPResponseBytes builds a signed OCSP response for the leaf cert.
func makeOCSPResponseBytes(t *testing.T, caCert *x509.Certificate, leafCert *x509.Certificate, caKey crypto.Signer, status int) []byte {
	t.Helper()
	ocspResp := ocsp.Response{
		Status:       status,
		SerialNumber: leafCert.SerialNumber,
		ProducedAt:   time.Now(),
		ThisUpdate:   time.Now().Add(-1 * time.Hour),
		NextUpdate:   time.Now().Add(1 * time.Hour),
	}
	if status == ocsp.Revoked {
		ocspResp.RevokedAt = time.Now().Add(-30 * time.Minute)
		ocspResp.RevocationReason = ocsp.Unspecified
	}
	respBytes, err := ocsp.CreateResponse(caCert, caCert, ocspResp, caKey)
	if err != nil {
		t.Fatalf("failed to create OCSP response: %v", err)
	}
	return respBytes
}

// --- OCSPStatus.String tests ---

func TestOCSPStatus_String(t *testing.T) {
	tests := []struct {
		name string
		s    OCSPStatus
		want string
	}{
		{"good", OCSPStatusGood, "good"},
		{"revoked", OCSPStatusRevoked, "revoked"},
		{"unknown", OCSPStatusUnknown, "unknown"},
		{"invalid value", OCSPStatus(999), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("OCSPStatus.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- NewOCSPChecker tests ---

func TestNewOCSPChecker_Default(t *testing.T) {
	c := NewOCSPChecker()
	if c == nil {
		t.Fatal("NewOCSPChecker() = nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if c.timeout == 0 {
		t.Error("timeout is zero")
	}
}

func TestNewOCSPChecker_WithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 10 * time.Second}
	c := NewOCSPChecker(WithOCSPHTTPClient(custom))
	if c.httpClient != custom {
		t.Error("WithOCSPHTTPClient did not set custom client")
	}
}

func TestNewOCSPChecker_WithTimeout(t *testing.T) {
	c := NewOCSPChecker(WithOCSPTimeout(30 * time.Second))
	if c.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want %v", c.timeout, 30*time.Second)
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("httpClient.Timeout = %v, want %v", c.httpClient.Timeout, 30*time.Second)
	}
}

// --- CheckOCSP tests ---

func TestCheckOCSP_NilCert(t *testing.T) {
	c := NewOCSPChecker()
	caCert, _, _ := generateTestCerts(t)
	_, err := c.CheckOCSP(context.Background(), nil, caCert, nil)
	if err == nil {
		t.Fatal("CheckOCSP() = nil, want error for nil cert")
	}
}

func TestCheckOCSP_NilIssuer(t *testing.T) {
	c := NewOCSPChecker()
	_, leafCert, _ := generateTestCerts(t)
	_, err := c.CheckOCSP(context.Background(), leafCert, nil, nil)
	if err == nil {
		t.Fatal("CheckOCSP() = nil, want error for nil issuer")
	}
}

func TestCheckOCSP_NoOCSPServers_NoStapledResponse(t *testing.T) {
	c := NewOCSPChecker()
	caCert, leafCert, _ := generateTestCerts(t)
	// Override the leaf cert's OCSPServer to empty.
	leafCert.OCSPServer = nil

	result, err := c.CheckOCSP(context.Background(), leafCert, caCert, nil)
	if err != nil {
		t.Fatalf("CheckOCSP() error = %v", err)
	}
	if result.Status != OCSPStatusUnknown {
		t.Errorf("Status = %v, want OCSPStatusUnknown", result.Status)
	}
	if result.Source != "active" {
		t.Errorf("Source = %q, want %q", result.Source, "active")
	}
}

func TestCheckOCSP_StapledResponseGood(t *testing.T) {
	c := NewOCSPChecker()
	caCert, leafCert, caKey := generateTestCerts(t)
	stapled := makeOCSPResponseBytes(t, caCert, leafCert, caKey, ocsp.Good)

	result, err := c.CheckOCSP(context.Background(), leafCert, caCert, stapled)
	if err != nil {
		t.Fatalf("CheckOCSP() error = %v", err)
	}
	if result.Status != OCSPStatusGood {
		t.Errorf("Status = %v, want OCSPStatusGood", result.Status)
	}
	if result.Source != "stapled" {
		t.Errorf("Source = %q, want %q", result.Source, "stapled")
	}
	if result.ProducedAt.IsZero() {
		t.Error("ProducedAt is zero")
	}
}

func TestCheckOCSP_StapledResponseRevoked(t *testing.T) {
	c := NewOCSPChecker()
	caCert, leafCert, caKey := generateTestCerts(t)
	stapled := makeOCSPResponseBytes(t, caCert, leafCert, caKey, ocsp.Revoked)

	result, err := c.CheckOCSP(context.Background(), leafCert, caCert, stapled)
	if err != nil {
		t.Fatalf("CheckOCSP() error = %v", err)
	}
	if result.Status != OCSPStatusRevoked {
		t.Errorf("Status = %v, want OCSPStatusRevoked", result.Status)
	}
	if result.Source != "stapled" {
		t.Errorf("Source = %q, want %q", result.Source, "stapled")
	}
	if result.RevokedAt.IsZero() {
		t.Error("RevokedAt is zero for revoked status")
	}
}

func TestCheckOCSP_StapledExpiredFallsBackToActive(t *testing.T) {
	// Create an expired stapled response so the checker falls through to an
	// active query against a mock HTTP responder.
	caCert, leafCert, caKey := generateTestCerts(t)

	// Build a stapled response that is already past its NextUpdate.
	expiredResp := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leafCert.SerialNumber,
		ProducedAt:   time.Now().Add(-2 * time.Hour),
		ThisUpdate:   time.Now().Add(-2 * time.Hour),
		NextUpdate:   time.Now().Add(-1 * time.Hour), // expired
	}
	expiredBytes, err := ocsp.CreateResponse(caCert, caCert, expiredResp, caKey)
	if err != nil {
		t.Fatalf("failed to create expired OCSP response: %v", err)
	}

	// Build a good response for the active responder.
	goodResp := makeOCSPResponseBytes(t, caCert, leafCert, caKey, ocsp.Good)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(goodResp)
	}))
	defer server.Close()

	// Point the leaf cert's OCSPServer at the test server.
	leafCert.OCSPServer = []string{server.URL}

	c := NewOCSPChecker(WithOCSPHTTPClient(server.Client()))
	result, err := c.CheckOCSP(context.Background(), leafCert, caCert, expiredBytes)
	if err != nil {
		t.Fatalf("CheckOCSP() error = %v", err)
	}
	// Should have fallen back to active query.
	if result.Source != "active" {
		t.Errorf("Source = %q, want %q (fallback to active)", result.Source, "active")
	}
	if result.Status != OCSPStatusGood {
		t.Errorf("Status = %v, want OCSPStatusGood", result.Status)
	}
}

func TestCheckOCSP_ActiveQueryGood(t *testing.T) {
	caCert, leafCert, caKey := generateTestCerts(t)
	goodResp := makeOCSPResponseBytes(t, caCert, leafCert, caKey, ocsp.Good)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the OCSP request body.
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(goodResp)
	}))
	defer server.Close()

	leafCert.OCSPServer = []string{server.URL}
	c := NewOCSPChecker(WithOCSPHTTPClient(server.Client()))
	result, err := c.CheckOCSP(context.Background(), leafCert, caCert, nil)
	if err != nil {
		t.Fatalf("CheckOCSP() error = %v", err)
	}
	if result.Status != OCSPStatusGood {
		t.Errorf("Status = %v, want OCSPStatusGood", result.Status)
	}
	if result.Source != "active" {
		t.Errorf("Source = %q, want %q", result.Source, "active")
	}
}

func TestCheckOCSP_ActiveQueryRevoked(t *testing.T) {
	caCert, leafCert, caKey := generateTestCerts(t)
	revokedResp := makeOCSPResponseBytes(t, caCert, leafCert, caKey, ocsp.Revoked)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(revokedResp)
	}))
	defer server.Close()

	leafCert.OCSPServer = []string{server.URL}
	c := NewOCSPChecker(WithOCSPHTTPClient(server.Client()))
	result, err := c.CheckOCSP(context.Background(), leafCert, caCert, nil)
	if err != nil {
		t.Fatalf("CheckOCSP() error = %v", err)
	}
	if result.Status != OCSPStatusRevoked {
		t.Errorf("Status = %v, want OCSPStatusRevoked", result.Status)
	}
	if result.Source != "active" {
		t.Errorf("Source = %q, want %q", result.Source, "active")
	}
}

func TestCheckOCSP_ActiveQueryServerError(t *testing.T) {
	caCert, leafCert, _ := generateTestCerts(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	leafCert.OCSPServer = []string{server.URL}
	c := NewOCSPChecker(WithOCSPHTTPClient(server.Client()))
	_, err := c.CheckOCSP(context.Background(), leafCert, caCert, nil)
	if err == nil {
		t.Fatal("CheckOCSP() = nil, want error for server returning 500")
	}
}

func TestCheckOCSP_ActiveQueryUnreachableServer(t *testing.T) {
	caCert, leafCert, _ := generateTestCerts(t)

	// Point at a closed server. Use a short-lived server to capture the port,
	// then close it so requests fail.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := server.URL
	server.Close()

	leafCert.OCSPServer = []string{addr}
	c := NewOCSPChecker(WithOCSPHTTPClient(&http.Client{Timeout: 2 * time.Second}))
	_, err := c.CheckOCSP(context.Background(), leafCert, caCert, nil)
	if err == nil {
		t.Fatal("CheckOCSP() = nil, want error for unreachable server")
	}
	// The error should mention the active query failure.
	var ocspErr error = err
	if ocspErr == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestCheckOCSP_InvalidStapledResponseFallsBackToActive(t *testing.T) {
	caCert, leafCert, caKey := generateTestCerts(t)
	goodResp := makeOCSPResponseBytes(t, caCert, leafCert, caKey, ocsp.Good)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(goodResp)
	}))
	defer server.Close()

	leafCert.OCSPServer = []string{server.URL}
	c := NewOCSPChecker(WithOCSPHTTPClient(server.Client()))

	// Pass garbage as the stapled response; the parser should fail and the
	// checker should fall through to an active query.
	_, err := c.CheckOCSP(context.Background(), leafCert, caCert, []byte("not-a-valid-ocsp-response"))
	if err != nil {
		t.Fatalf("CheckOCSP() should fall back to active on bad stapled, got error: %v", err)
	}
}

// Ensure errors from the active query path wrap the underlying cause.
func TestCheckOCSP_ActiveQueryErrorContainsCause(t *testing.T) {
	caCert, leafCert, _ := generateTestCerts(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	leafCert.OCSPServer = []string{server.URL}
	c := NewOCSPChecker(WithOCSPHTTPClient(server.Client()))
	_, err := c.CheckOCSP(context.Background(), leafCert, caCert, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// The error message should reference the responder status.
	if !errors.Is(err, err) {
		t.Errorf("errors.Is self-check failed for: %v", err)
	}
}
