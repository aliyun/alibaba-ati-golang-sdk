package ati

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// --- resolveIdentityHost / resolveAccessHost ---

func TestResolveIdentityHost_WhenSet(t *testing.T) {
	client := &AgentClient{identityHost: "identity.example.com"}
	got := client.resolveIdentityHost("connection.example.com")
	if got != "identity.example.com" {
		t.Errorf("resolveIdentityHost() = %q, want %q", got, "identity.example.com")
	}
}

func TestResolveIdentityHost_WhenEmpty(t *testing.T) {
	client := &AgentClient{}
	got := client.resolveIdentityHost("connection.example.com")
	if got != "connection.example.com" {
		t.Errorf("resolveIdentityHost() = %q, want %q", got, "connection.example.com")
	}
}

func TestResolveAccessHost_WhenSet(t *testing.T) {
	client := &AgentClient{accessHost: "access.example.com"}
	got := client.resolveAccessHost("connection.example.com")
	if got != "access.example.com" {
		t.Errorf("resolveAccessHost() = %q, want %q", got, "access.example.com")
	}
}

func TestResolveAccessHost_WhenEmpty(t *testing.T) {
	client := &AgentClient{}
	got := client.resolveAccessHost("connection.example.com")
	if got != "connection.example.com" {
		t.Errorf("resolveAccessHost() = %q, want %q", got, "connection.example.com")
	}
}

// --- checkDNSDiscovery ---

func mustNewFqdn(t *testing.T, domain string) models.Fqdn {
	t.Helper()
	f, err := models.NewFqdn(domain)
	if err != nil {
		t.Fatalf("models.NewFqdn(%q) error = %v", domain, err)
	}
	return f
}

func TestCheckDNSDiscovery_DNSError(t *testing.T) {
	resolver := verify.NewMockDNSResolver().
		WithError("agent.example.com", errors.New("DNS SERVFAIL"))
	client := &AgentClient{dnsResolver: resolver}

	ctx := context.Background()
	fqdn := mustNewFqdn(t, "agent.example.com")
	found, agentID := client.checkDNSDiscovery(ctx, fqdn)
	if found {
		t.Error("checkDNSDiscovery() found = true, want false on DNS error")
	}
	if agentID != "" {
		t.Errorf("checkDNSDiscovery() agentID = %q, want empty on DNS error", agentID)
	}
}

func TestCheckDNSDiscovery_NotFound(t *testing.T) {
	resolver := verify.NewMockDNSResolver() // no records configured
	client := &AgentClient{dnsResolver: resolver}

	ctx := context.Background()
	fqdn := mustNewFqdn(t, "agent.example.com")
	found, agentID := client.checkDNSDiscovery(ctx, fqdn)
	if found {
		t.Error("checkDNSDiscovery() found = true, want false when not found")
	}
	if agentID != "" {
		t.Errorf("checkDNSDiscovery() agentID = %q, want empty when not found", agentID)
	}
}

func TestCheckDNSDiscovery_FoundWithRecords(t *testing.T) {
	resolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*verify.ATIRecord{
			{ID: "agent-123", RA: "aliyun"},
		})
	client := &AgentClient{dnsResolver: resolver}

	ctx := context.Background()
	fqdn := mustNewFqdn(t, "agent.example.com")
	found, agentID := client.checkDNSDiscovery(ctx, fqdn)
	if !found {
		t.Error("checkDNSDiscovery() found = false, want true")
	}
	if agentID != "agent-123" {
		t.Errorf("checkDNSDiscovery() agentID = %q, want %q", agentID, "agent-123")
	}
}

func TestCheckDNSDiscovery_FoundMultipleRecordsReturnsFirstID(t *testing.T) {
	resolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*verify.ATIRecord{
			{ID: "first-agent", RA: "aliyun"},
			{ID: "second-agent", RA: "aliyun"},
		})
	client := &AgentClient{dnsResolver: resolver}

	ctx := context.Background()
	fqdn := mustNewFqdn(t, "agent.example.com")
	found, agentID := client.checkDNSDiscovery(ctx, fqdn)
	if !found {
		t.Error("checkDNSDiscovery() found = false, want true")
	}
	if agentID != "first-agent" {
		t.Errorf("checkDNSDiscovery() agentID = %q, want %q (first record)", agentID, "first-agent")
	}
}

func TestCheckDNSDiscovery_EmptyRecordsSlice(t *testing.T) {
	// The mock returns Found=false when the records slice is empty,
	// so checkDNSDiscovery returns (false, "").
	resolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*verify.ATIRecord{})
	client := &AgentClient{dnsResolver: resolver}

	ctx := context.Background()
	fqdn := mustNewFqdn(t, "agent.example.com")
	found, agentID := client.checkDNSDiscovery(ctx, fqdn)
	if found {
		t.Error("checkDNSDiscovery() found = true, want false when records slice is empty")
	}
	if agentID != "" {
		t.Errorf("checkDNSDiscovery() agentID = %q, want empty", agentID)
	}
}

// --- Prefetch ---

func TestPrefetch_InvalidHost(t *testing.T) {
	resolver := verify.NewMockDNSResolver()
	client := &AgentClient{dnsResolver: resolver}

	err := client.Prefetch(context.Background(), "")
	if err == nil {
		t.Fatal("Prefetch() with empty host: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid host") {
		t.Errorf("Prefetch() error = %q, want to contain %q", err.Error(), "invalid host")
	}
}

func TestPrefetch_InvalidHostBadLabel(t *testing.T) {
	resolver := verify.NewMockDNSResolver()
	client := &AgentClient{dnsResolver: resolver}

	// A host with an invalid label (starts with hyphen) is rejected by NewFqdn.
	err := client.Prefetch(context.Background(), "-invalid.example.com")
	if err == nil {
		t.Fatal("Prefetch() with invalid host: expected error, got nil")
	}
}

func TestPrefetch_DNSNotFound(t *testing.T) {
	resolver := verify.NewMockDNSResolver() // no records
	client := &AgentClient{dnsResolver: resolver}

	err := client.Prefetch(context.Background(), "agent.example.com")
	if err == nil {
		t.Fatal("Prefetch() with no DNS record: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no _ati TXT record") {
		t.Errorf("Prefetch() error = %q, want to contain %q", err.Error(), "no _ati TXT record")
	}
}

func TestPrefetch_DNSFound(t *testing.T) {
	resolver := verify.NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*verify.ATIRecord{
			{ID: "agent-456", RA: "aliyun"},
		})
	client := &AgentClient{dnsResolver: resolver}

	err := client.Prefetch(context.Background(), "agent.example.com")
	if err != nil {
		t.Errorf("Prefetch() with DNS record found: unexpected error = %v", err)
	}
}

func TestPrefetch_DNSError(t *testing.T) {
	resolver := verify.NewMockDNSResolver().
		WithError("agent.example.com", errors.New("network timeout"))
	client := &AgentClient{dnsResolver: resolver}

	err := client.Prefetch(context.Background(), "agent.example.com")
	if err == nil {
		t.Fatal("Prefetch() with DNS error: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no _ati TXT record") {
		t.Errorf("Prefetch() error = %q, want to contain %q", err.Error(), "no _ati TXT record")
	}
}

// --- buildClientVerifyConnection ---

func TestBuildClientVerifyConnection_NoPeerCertificates(t *testing.T) {
	cfg := &agentClientConfig{}
	verifyFn := buildClientVerifyConnection(cfg, nil)

	cs := tls.ConnectionState{PeerCertificates: nil}
	if err := verifyFn(cs); err != nil {
		t.Errorf("verifyFn() with nil peer certs: unexpected error = %v", err)
	}

	cs = tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
	if err := verifyFn(cs); err != nil {
		t.Errorf("verifyFn() with empty peer certs: unexpected error = %v", err)
	}
}

func TestBuildClientVerifyConnection_ValidCertificate(t *testing.T) {
	cert := generateTestCert(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(1*time.Hour),
	)

	cfg := &agentClientConfig{}
	verifyFn := buildClientVerifyConnection(cfg, nil)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if err := verifyFn(cs); err != nil {
		t.Errorf("verifyFn() with valid cert: unexpected error = %v", err)
	}
}

func TestBuildClientVerifyConnection_ExpiredCertificate(t *testing.T) {
	cert := generateTestCert(t,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	)

	cfg := &agentClientConfig{}
	verifyFn := buildClientVerifyConnection(cfg, nil)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("verifyFn() with expired cert: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "peer certificate invalid") {
		t.Errorf("verifyFn() error = %q, want to contain %q", err.Error(), "peer certificate invalid")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("verifyFn() error = %q, want to contain %q", err.Error(), "expired")
	}
}

func TestBuildClientVerifyConnection_NotYetValidCertificate(t *testing.T) {
	cert := generateTestCert(t,
		time.Now().Add(1*time.Hour), // NotBefore is in the future
		time.Now().Add(2*time.Hour),
	)

	cfg := &agentClientConfig{}
	verifyFn := buildClientVerifyConnection(cfg, nil)

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := verifyFn(cs)
	if err == nil {
		t.Fatal("verifyFn() with not-yet-valid cert: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "peer certificate invalid") {
		t.Errorf("verifyFn() error = %q, want to contain %q", err.Error(), "peer certificate invalid")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("verifyFn() error = %q, want to contain %q", err.Error(), "not yet valid")
	}
}

// --- helpers ---

// generateTestCert creates a self-signed ECDSA certificate for testing.
func generateTestCert(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-agent.example.com",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert
}
