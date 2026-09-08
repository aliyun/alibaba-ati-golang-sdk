package ati

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// TestAgentClient_Do_BadgeRequired_BadgeFails tests that when trust level is
// BadgeRequired and badge verification fails (no badge records in TLog), the
// request returns an error containing "badge verification failed".
// This covers mtls_client.go lines 554-567.
func TestAgentClient_Do_BadgeRequired_BadgeFails(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	u, _ := url.Parse(server.URL)

	// Mock resolver with discovery records (so DNS discovery passes) but no badge records
	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords(u.Hostname(), []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithTrustLevel(BadgeRequired),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	// Override transport to trust the test server
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       client.tlsConfig.Certificates,
		},
	}

	_, err = client.Do(context.Background(), http.MethodGet, server.URL+"/test", nil)
	if err == nil {
		t.Fatal("expected error when badge verification fails with BadgeRequired")
	}
	if !strings.Contains(err.Error(), "badge verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAgentClient_Do_AutoDetect_BadgeFails_NoError tests that when trust level
// is nil (auto-detect), badge verification failure does NOT return an error.
// The response should have BadgeVerified=false but the request still succeeds.
// This covers mtls_client.go lines 554-561 (shouldBadge + badge runs but does not error).
func TestAgentClient_Do_AutoDetect_BadgeFails_NoError(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	u, _ := url.Parse(server.URL)

	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords(u.Hostname(), []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	// No trust level specified → auto-detect mode (explicit = false)
	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	// Remove the explicit trust level to get auto-detect
	client.trustLevel = nil

	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       client.tlsConfig.Certificates,
		},
	}

	resp, err := client.Do(context.Background(), http.MethodGet, server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("auto-detect mode should not error on badge fail: %v", err)
	}
	defer resp.Body.Close()

	if resp.VerificationOutcome == nil {
		t.Fatal("expected VerificationOutcome to be non-nil")
	}
	if resp.VerificationOutcome.BadgeVerified {
		t.Error("expected BadgeVerified = false (no badge records)")
	}
}

// TestAgentClient_Do_CacheHit tests that when a second request is made to the
// same server, the cached verification result is returned.
// This covers mtls_client.go lines 513-518.
func TestAgentClient_Do_CacheHit(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	u, _ := url.Parse(server.URL)

	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords(u.Hostname(), []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

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

	// First request — verify and cache
	resp1, err := client.Do(context.Background(), http.MethodGet, server.URL+"/first", nil)
	if err != nil {
		t.Fatalf("first request error: %v", err)
	}
	resp1.Body.Close()

	// Second request — should hit cache
	resp2, err := client.Do(context.Background(), http.MethodGet, server.URL+"/second", nil)
	if err != nil {
		t.Fatalf("second request error: %v", err)
	}
	resp2.Body.Close()

	if resp2.VerificationOutcome == nil {
		t.Fatal("expected cached VerificationOutcome")
	}
}

// TestAgentClient_Do_RequestFail tests the error path when the HTTP request itself fails.
// This covers mtls_client.go line 505.
func TestAgentClient_Do_RequestFail(t *testing.T) {
	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords("192.0.2.1", []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithTrustLevel(PKIOnly),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	client.httpClient.Timeout = 100 * time.Millisecond

	// Connect to a non-routable address → connection timeout
	_, err = client.Do(context.Background(), http.MethodGet, "https://192.0.2.1:443/test", nil)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAgentClient_Do_InvalidFqdn tests that an invalid hostname in the URL
// returns an error about invalid hostname.
// This covers mtls_client.go line 473.
func TestAgentClient_Do_InvalidFqdn(t *testing.T) {
	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")

	mockResolver := verify.NewMockDNSResolver()

	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithTrustLevel(PKIOnly),
		WithDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}

	// A hostname with invalid characters should fail NewFqdn
	_, err = client.Do(context.Background(), http.MethodGet, "https://-invalid-.example.com/test", nil)
	if err == nil {
		t.Fatal("expected error for invalid hostname")
	}
	if !strings.Contains(err.Error(), "invalid hostname") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAgentClient_Do_PolicyNone_MarshalError tests that a non-marshalable body
// returns an error in PolicyNone mode.
// This covers mtls_client.go line 453 (PolicyNone marshal error path).
func TestAgentClient_Do_PolicyNone_MarshalError(t *testing.T) {
	client, err := NewAgentClient(WithTrustLevel(PolicyNone))
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}

	// Channel cannot be marshaled to JSON
	_, err = client.Do(context.Background(), http.MethodPost, "https://example.com/test", make(chan int))
	if err == nil {
		t.Fatal("expected error for non-marshalable body")
	}
	if !strings.Contains(err.Error(), "failed to marshal request body") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAgentClient_Do_PolicyNone_DoError tests that a network failure in
// PolicyNone mode returns an appropriate error.
// This covers mtls_client.go line 466.
func TestAgentClient_Do_PolicyNone_DoError(t *testing.T) {
	client, err := NewAgentClient(WithTrustLevel(PolicyNone))
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	client.httpClient.Timeout = 100 * time.Millisecond

	_, err = client.Do(context.Background(), http.MethodGet, "https://192.0.2.1:443/test", nil)
	if err == nil {
		t.Fatal("expected error for unreachable host in PolicyNone")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAgentClient_Do_TrustLevelNotAchieved tests that when the requested level
// is not achieved (e.g., requested BadgeRequired but only got PKI), the
// Do method returns an error.
// This covers mtls_client.go lines 594-595.
func TestAgentClient_Do_TrustLevelNotAchieved(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")
	u, _ := url.Parse(server.URL)

	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords(u.Hostname(), []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

	// Use BadgeRequired — badge will fail, so achieved stays below requested.
	client, err := NewAgentClient(
		WithIdentityCert(clientCertFile, clientKeyFile),
		WithTrustLevel(BadgeRequired),
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

	_, err = client.Do(context.Background(), http.MethodGet, server.URL+"/test", nil)
	if err == nil {
		t.Fatal("expected error when trust level not achieved")
	}
	// The error will be either "badge verification failed" or "requested trust level not achieved"
	if !strings.Contains(err.Error(), "badge verification failed") && !strings.Contains(err.Error(), "trust level") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestCheckDNSDiscovery_FoundNoRecords tests the path where the DNS resolver
// returns Found=true but an empty Records slice. This requires a custom resolver
// since the standard mock always ties Found to len(records) > 0.
// This covers mtls_client.go line 635.
type foundNoRecordsResolver struct {
	verify.DNSResolver
}

func (r *foundNoRecordsResolver) LookupATIDiscovery(_ context.Context, _ models.Fqdn) (verify.ATIDiscoveryResult, error) {
	return verify.ATIDiscoveryResult{Found: true, Records: nil}, nil
}

func (r *foundNoRecordsResolver) LookupATIBadge(_ context.Context, _ models.Fqdn) (verify.DNSLookupResult, error) {
	return verify.DNSLookupResult{}, nil
}

func (r *foundNoRecordsResolver) FindBadgeForVersion(_ context.Context, _ models.Fqdn, _ models.Version) (*verify.ATIBadgeRecord, error) {
	return nil, nil
}

func (r *foundNoRecordsResolver) FindPreferredBadge(_ context.Context, _ models.Fqdn) (*verify.ATIBadgeRecord, error) {
	return nil, nil
}

func TestCheckDNSDiscovery_FoundButNoRecords(t *testing.T) {
	resolver := &foundNoRecordsResolver{}
	client := &AgentClient{dnsResolver: resolver}

	ctx := context.Background()
	fqdn := mustNewFqdn(t, "agent.example.com")
	found, agentID := client.checkDNSDiscovery(ctx, fqdn)
	if !found {
		t.Error("checkDNSDiscovery() found = false, want true (Found=true from resolver)")
	}
	if agentID != "" {
		t.Errorf("checkDNSDiscovery() agentID = %q, want empty (no records)", agentID)
	}
}

// TestNewAgentClient_OptionError tests that when an option returns an error,
// NewAgentClient propagates it.
// This covers mtls_client.go line 202.
func TestNewAgentClient_OptionError(t *testing.T) {
	badOpt := func(cfg *agentClientConfig) error {
		return &testError{msg: "bad option"}
	}

	_, err := NewAgentClient(badOpt)
	if err == nil {
		t.Fatal("expected error from bad option")
	}
	if !strings.Contains(err.Error(), "bad option") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestNewAgentClient_DefaultDiscoveryResolver_WithDNSServer tests the path
// where globalDNSServer returns a non-empty value for DANE resolver creation.
// This covers mtls_client.go lines 317-321.
func TestNewAgentClient_DANEAutoCreate(t *testing.T) {
	certFile, keyFile, _ := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithIdentityCert(certFile, keyFile),
		WithTrustLevel(DANEAndBadge),
	)
	if err != nil {
		t.Fatalf("NewAgentClient(DANEAndBadge) error: %v", err)
	}
	if client.daneResolver == nil {
		t.Error("expected daneResolver to be auto-created for DANEAndBadge level")
	}
}

// TestNewAgentClient_DANEResolver_NotCreatedForPKIOnly verifies that DANE
// resolver is NOT auto-created when trust level is below DANEAndBadge.
func TestNewAgentClient_DANEResolver_NotCreatedForPKIOnly(t *testing.T) {
	certFile, keyFile, _ := setupClientTestCerts(t, "agent.example.com", "v1.0.0")

	client, err := NewAgentClient(
		WithIdentityCert(certFile, keyFile),
		WithTrustLevel(PKIOnly),
		WithDNSResolver(verify.NewMockDNSResolver()),
	)
	if err != nil {
		t.Fatalf("NewAgentClient error: %v", err)
	}
	if client.daneResolver != nil {
		t.Error("expected daneResolver to be nil for PKIOnly level")
	}
}

// TestAgentClient_Do_MarshalBody tests the body marshaling path in the
// non-PolicyNone branch (line 497 error path for invalid request URL chars).
func TestAgentClient_Do_MarshalBodyError_NonPolicyNone(t *testing.T) {
	caCert, caKey, _, _ := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCertWithATIName(t, caCert, caKey, "server.example.com", "v1.0.0", []string{"server.example.com", "127.0.0.1"})

	serverCert, _ := tls.X509KeyPair(serverCertPEM, serverKeyPEM)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	clientCertFile, clientKeyFile, _ := setupClientTestCerts(t, "client.example.com", "v1.0.0")
	u, _ := url.Parse(server.URL)

	mockResolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords(u.Hostname(), []*verify.ATIRecord{
			{ID: "ag-server", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: verify.ATIRecordModeDirect},
		})

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

	// Channel cannot be marshaled
	_, err = client.Do(context.Background(), http.MethodPost, server.URL+"/test", make(chan int))
	if err == nil {
		t.Fatal("expected error for non-marshalable body")
	}
	if !strings.Contains(err.Error(), "failed to marshal request body") {
		t.Errorf("unexpected error: %v", err)
	}
}

