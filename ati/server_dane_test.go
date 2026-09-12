package ati

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify/crl"
)

// TestBuildVerifyConnection_DANE_PassPath tests the full DANE verification flow:
// badge passes → DANE passes → achieved level = DANEAndBadge.
// This covers server.go lines 332-363 (DANE verification block).
func TestBuildVerifyConnection_DANE_PassPath(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	// Compute fingerprint (SHA-256 of DER)
	fpBytes := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fpBytes[:])

	// Set up mock DNS resolver with badge records
	badgeURL := fmt.Sprintf("https://%s/api/v1/badge/client.example.com/v1.0.0", verify.DefaultTrustedTLHost)
	v100 := models.NewVersion(1, 0, 0)
	mockResolver := verify.NewMockDNSResolver().
		WithRecords("client.example.com", []verify.ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	// Set up mock TLog client returning matching response
	// ATI name in cert is ati://v1.0.0.client.example.com (host = "v1.0.0.client.example.com")
	mockTLog := verify.NewMockTransparencyLogClient().
		WithTLResponse(badgeURL, &models.TLResponse{
			Status:        "success",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentName:   "ati://v1.0.0.client.example.com",
				AgentHost:   "client.example.com",
				AgentStatus: "ACTIVE",
				Certificates: models.TLCertificates{
					IdentityCertFingerprint: "SHA256:" + fpHex,
				},
			},
		})

	// Set up DANE resolver with identity TLSA records matching the cert's SPKI fingerprint
	spkiFP := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiFP[:])
	mockDANE := verify.NewMockDANEResolver().
		WithIdentityTLSA("client.example.com", verify.TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records: []verify.TLSARecord{
				{Usage: 3, Selector: 1, MatchingType: 1, CertHash: spkiHex},
			},
		})

	level := DANEAndBadge
	cfg := &serverConfig{
		trustLevel:   &level,
		dnsResolver:  mockResolver,
		daneResolver: mockDANE,
		clientVerifier: verify.NewClientVerifier(
			verify.WithDNSResolver(mockResolver),
			verify.WithTlogClient(mockTLog),
			verify.WithTrustedTLHost(verify.DefaultTrustedTLHost),
		),
		peerLevels: &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err != nil {
		t.Fatalf("expected DANE to pass, got error: %v", err)
	}
}

// TestBuildVerifyConnection_DANE_Reject tests that DANE rejection
// returns an error in explicit mode.
// This covers server.go lines 353-357.
func TestBuildVerifyConnection_DANE_Reject(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	fpBytes := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fpBytes[:])

	badgeURL := fmt.Sprintf("https://%s/api/v1/badge/client.example.com/v1.0.0", verify.DefaultTrustedTLHost)
	v100 := models.NewVersion(1, 0, 0)
	mockResolver := verify.NewMockDNSResolver().
		WithRecords("client.example.com", []verify.ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	mockTLog := verify.NewMockTransparencyLogClient().
		WithTLResponse(badgeURL, &models.TLResponse{
			Status:        "success",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentName:   "ati://v1.0.0.client.example.com",
				AgentHost:   "client.example.com",
				AgentStatus: "ACTIVE",
				Certificates: models.TLCertificates{
					IdentityCertFingerprint: "SHA256:" + fpHex,
				},
			},
		})

	// DANE resolver returns records with WRONG fingerprint → DANEMismatch → reject
	mockDANE := verify.NewMockDANEResolver().
		WithIdentityTLSA("client.example.com", verify.TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records: []verify.TLSARecord{
				{Usage: 3, Selector: 1, MatchingType: 1, CertHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
			},
		})

	level := DANEAndBadge
	cfg := &serverConfig{
		trustLevel:   &level,
		dnsResolver:  mockResolver,
		daneResolver: mockDANE,
		clientVerifier: verify.NewClientVerifier(
			verify.WithDNSResolver(mockResolver),
			verify.WithTlogClient(mockTLog),
			verify.WithTrustedTLHost(verify.DefaultTrustedTLHost),
		),
		peerLevels: &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected DANE rejection error")
	}
	if !strings.Contains(err.Error(), "DANE verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestBuildVerifyConnection_DANE_NoRecords_AutoDetect tests that DANE with no
// records in auto-detect mode passes (does not error).
// This covers the DANE block with IsPass() → achieved = DANEAndBadge not reached
// but also no error returned (line 358 not hit, but 332-350 flow exercised).
func TestBuildVerifyConnection_DANE_NoRecords_AutoDetect(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	fpBytes := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fpBytes[:])

	badgeURL := fmt.Sprintf("https://%s/api/v1/badge/client.example.com/v1.0.0", verify.DefaultTrustedTLHost)
	v100 := models.NewVersion(1, 0, 0)
	mockResolver := verify.NewMockDNSResolver().
		WithRecords("client.example.com", []verify.ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	mockTLog := verify.NewMockTransparencyLogClient().
		WithTLResponse(badgeURL, &models.TLResponse{
			Status:        "success",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentName:   "ati://v1.0.0.client.example.com",
				AgentHost:   "client.example.com",
				AgentStatus: "ACTIVE",
				Certificates: models.TLCertificates{
					IdentityCertFingerprint: "SHA256:" + fpHex,
				},
			},
		})

	// DANE resolver returns no records → DANENoRecords → IsPass() = true
	mockDANE := verify.NewMockDANEResolver()

	// auto-detect mode (trustLevel = nil)
	cfg := &serverConfig{
		trustLevel:   nil,
		dnsResolver:  mockResolver,
		daneResolver: mockDANE,
		clientVerifier: verify.NewClientVerifier(
			verify.WithDNSResolver(mockResolver),
			verify.WithTlogClient(mockTLog),
			verify.WithTrustedTLHost(verify.DefaultTrustedTLHost),
		),
		peerLevels: &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err != nil {
		t.Fatalf("auto-detect mode with no DANE records should pass, got: %v", err)
	}
}

// TestBuildVerifyConnection_CRL_Reject tests that CRL rejection returns an error.
// This covers server.go lines 290-291.
func TestBuildVerifyConnection_CRL_Reject(t *testing.T) {
	// Create a CA that can sign both certs and CRLs
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key gen: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CRL CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// Create a leaf cert with a CRL distribution point and ATI URI SAN
	leafSerial := big.NewInt(42)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Start CRL server BEFORE creating the cert (need the URL for CDP)
	crlData := generateRevokedCRL(t, caCert, caKey, leafSerial)
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlData)
	}))
	defer crlServer.Close()

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "client.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"client.example.com"},
		URIs:         []*url.URL{{Scheme: "ati", Host: "client.example.com", Path: "/v1.0.0"}},
		CRLDistributionPoints: []string{crlServer.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	level := BadgeRequired
	checker := crl.NewChecker(crl.WithFetcher(crl.NewFetcher(crl.WithHTTPClient(crlServer.Client()), crl.WithAllowPrivateNetworks(true))))
	cfg := &serverConfig{
		trustLevel:     &level,
		clientVerifier: verify.NewClientVerifier(),
		peerLevels:     &sync.Map{},
		crlChecker:     checker,
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, caCert},
	}

	err = verifyFn(cs)
	if err == nil {
		t.Fatal("expected CRL rejection error")
	}
	if !strings.Contains(err.Error(), "CRL check failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestBuildVerifyConnection_CRL_FetchFail_Reject verifies fail-closed behavior
// per spec R6.3: when the CDP URI cannot be fetched (e.g. the server errors),
// the connection must be rejected, not silently allowed through.
func TestBuildVerifyConnection_CRL_FetchFail_Reject(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key gen: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CRL CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafSerial := big.NewInt(43)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// CRL server that always errors — simulates fetch failure.
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer crlServer.Close()

	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "client.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"client.example.com"},
		URIs:                  []*url.URL{{Scheme: "ati", Host: "client.example.com", Path: "/v1.0.0"}},
		CRLDistributionPoints: []string{crlServer.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	level := BadgeRequired
	checker := crl.NewChecker(crl.WithFetcher(crl.NewFetcher(crl.WithHTTPClient(crlServer.Client()), crl.WithAllowPrivateNetworks(true))))
	cfg := &serverConfig{
		trustLevel:     &level,
		clientVerifier: verify.NewClientVerifier(),
		peerLevels:     &sync.Map{},
		crlChecker:     checker,
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, caCert},
	}

	err = verifyFn(cs)
	if err == nil {
		t.Fatal("expected CRL fetch-failure to reject the connection (fail-closed)")
	}
	if !strings.Contains(err.Error(), "CRL check failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func generateRevokedCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, serial *big.Int) []byte {
	t.Helper()
	template := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: serial, RevocationTime: time.Now().Add(-1 * time.Hour)},
		},
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

// TestBuildVerifyConnection_TrustLevelNotAchieved_WithDANE tests that when badge
// passes but DANE fails (lookup error + explicit DANEAndBadge), verification is
// rejected. Explicit DANEAndBadge is a REQUIRED policy: any inconclusive or
// errored DANE outcome (not just an affirmative mismatch) must fail fast rather
// than silently falling through to a generic "not achieved" check.
func TestBuildVerifyConnection_TrustLevelNotAchieved_WithDANE(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	certPEM, _ := generateCertWithATIName(t, caCert, caKey, "client.example.com", "v1.0.0", []string{"client.example.com"})
	cert := parseTestCert(t, certPEM)

	fpBytes := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fpBytes[:])

	badgeURL := fmt.Sprintf("https://%s/api/v1/badge/client.example.com/v1.0.0", verify.DefaultTrustedTLHost)
	v100 := models.NewVersion(1, 0, 0)
	mockResolver := verify.NewMockDNSResolver().
		WithRecords("client.example.com", []verify.ATIBadgeRecord{
			{FormatVersion: "ati-badge1", Version: &v100, URL: badgeURL},
		})

	mockTLog := verify.NewMockTransparencyLogClient().
		WithTLResponse(badgeURL, &models.TLResponse{
			Status:        "success",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentName:   "ati://v1.0.0.client.example.com",
				AgentHost:   "client.example.com",
				AgentStatus: "ACTIVE",
				Certificates: models.TLCertificates{
					IdentityCertFingerprint: "SHA256:" + fpHex,
				},
			},
		})

	// DANE resolver returns an error → DANELookupError → IsPass()=false, IsReject()=false
	// This means achieved stays at BadgeRequired, which is below DANEAndBadge.
	mockDANE := verify.NewMockDANEResolver().
		WithIdentityError("client.example.com", fmt.Errorf("simulated DNS lookup failure"))

	level := DANEAndBadge
	cfg := &serverConfig{
		trustLevel:   &level,
		dnsResolver:  mockResolver,
		daneResolver: mockDANE,
		clientVerifier: verify.NewClientVerifier(
			verify.WithDNSResolver(mockResolver),
			verify.WithTlogClient(mockTLog),
			verify.WithTrustedTLHost(verify.DefaultTrustedTLHost),
		),
		peerLevels: &sync.Map{},
	}

	verifyFn := buildVerifyConnection(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err := verifyFn(cs)
	if err == nil {
		t.Fatal("expected DANE verification failure error")
	}
	if !strings.Contains(err.Error(), "DANE verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

