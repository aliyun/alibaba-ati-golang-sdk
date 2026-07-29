package verify

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func makeDiscoveryRecord(id, url string) *ATIRecord {
	return &ATIRecord{
		ID:      id,
		RA:      "aliyun",
		Version: models.NewVersion(1, 0, 0),
		Mode:    ATIRecordModeCard,
		URL:     url,
	}
}

func TestParallelDiscovery_AllRecordsFound(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")
	v := models.NewVersion(1, 0, 0)

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		}).
		WithRecords("agent.example.com", []ATIBadgeRecord{
			{FormatVersion: "ati-badge1", URL: "https://tl.example.com/badge/123", Version: &v},
		})

	daneMock := NewMockDANEResolver().WithTLSA("agent.example.com", 443, TLSALookupResult{
		Found:       true,
		DNSSECValid: true,
		Records:     []TLSARecord{{Usage: 3, Selector: 0, MatchingType: 1, CertHash: "abc123"}},
	})

	result, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, daneMock)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v", err)
	}
	if result == nil {
		t.Fatal("ParallelDiscovery() result is nil")
	}
	if result.AgentID != "agent-123" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "agent-123")
	}
	if result.AgentCardURL != "https://card.example.com/card.json" {
		t.Errorf("AgentCardURL = %q, want %q", result.AgentCardURL, "https://card.example.com/card.json")
	}
	if result.TLQueryURL != "https://tl.example.com/badge/123" {
		t.Errorf("TLQueryURL = %q, want %q", result.TLQueryURL, "https://tl.example.com/badge/123")
	}
	if result.DNSSECStatus != "fully_validated" {
		t.Errorf("DNSSECStatus = %q, want %q", result.DNSSECStatus, "fully_validated")
	}
	if len(result.IdentityTLSA) != 1 {
		t.Errorf("IdentityTLSA length = %d, want 1", len(result.IdentityTLSA))
	}
}

func TestParallelDiscovery_ATIDiscoveryFails_ReturnsError(t *testing.T) {
	fqdn, _ := models.NewFqdn("fail.example.com")

	dnsMock := NewMockDNSResolver().
		WithError("fail.example.com", errors.New("DNS lookup failed"))

	// When ATI discovery fails, AgentID is empty and firstErr is set, so
	// ParallelDiscovery returns the error.
	_, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, nil)
	if err == nil {
		t.Fatal("ParallelDiscovery() expected error when ATI discovery fails")
	}
}

func TestParallelDiscovery_ATIDiscoveryEmpty_ReturnsANSError(t *testing.T) {
	fqdn, _ := models.NewFqdn("empty.example.com")

	dnsMock := NewMockDNSResolver()
	// No discovery records configured => empty result

	_, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, nil)
	if err == nil {
		t.Fatal("ParallelDiscovery() expected error for missing _ati record")
	}

	var ansErr *ANSError
	if !errors.As(err, &ansErr) {
		t.Fatalf("expected *ANSError, got %T: %v", err, err)
	}
	if ansErr.Code != CodeDNSCoreRecordMissing {
		t.Errorf("error code = %q, want %q", ansErr.Code, CodeDNSCoreRecordMissing)
	}
}

func TestParallelDiscovery_BadgeLookupFailure_NonFatal(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	// ATI discovery succeeds, but badge lookup returns an error (configured via WithError
	// which affects both LookupATIBadge and LookupATIDiscovery). To make badge fail while
	// ATI succeeds, we need a custom resolver.
	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	// Override LookupATIBadge path by not configuring badge records and configuring an error.
	// However, WithError affects all lookups. We need a custom approach: use a separate
	// resolver that fails badge but succeeds discovery.
	failingBadgeMock := &badgeFailingResolver{
		MockDNSResolver: dnsMock,
	}

	result, err := ParallelDiscovery(context.Background(), fqdn, failingBadgeMock, nil)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v (badge failure should be non-fatal)", err)
	}
	if result == nil {
		t.Fatal("ParallelDiscovery() result is nil")
	}
	if result.AgentID != "agent-123" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "agent-123")
	}
	if result.TLQueryURL != "" {
		t.Errorf("TLQueryURL = %q, want empty (badge failed)", result.TLQueryURL)
	}
}

// badgeFailingResolver wraps MockDNSResolver but makes FindPreferredBadge return an error.
type badgeFailingResolver struct {
	*MockDNSResolver
}

func (r *badgeFailingResolver) FindPreferredBadge(_ context.Context, _ models.Fqdn) (*ATIBadgeRecord, error) {
	return nil, errors.New("badge lookup failed")
}

func TestParallelDiscovery_DANEResolverNil_SkipsTLSA(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	result, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, nil)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v", err)
	}
	if result == nil {
		t.Fatal("ParallelDiscovery() result is nil")
	}
	if result.AgentID != "agent-123" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "agent-123")
	}
	if len(result.IdentityTLSA) != 0 {
		t.Errorf("IdentityTLSA length = %d, want 0 (DANE resolver nil)", len(result.IdentityTLSA))
	}
	if result.DNSSECStatus != "" {
		t.Errorf("DNSSECStatus = %q, want empty (DANE resolver nil)", result.DNSSECStatus)
	}
}

func TestParallelDiscovery_DNSSECValidTrue_FullyValidated(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	daneMock := NewMockDANEResolver().WithTLSA("agent.example.com", 443, TLSALookupResult{
		Found:       true,
		DNSSECValid: true,
		Records:     []TLSARecord{{Usage: 3, Selector: 0, MatchingType: 1, CertHash: "deadbeef"}},
	})

	result, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, daneMock)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v", err)
	}
	if result.DNSSECStatus != "fully_validated" {
		t.Errorf("DNSSECStatus = %q, want %q", result.DNSSECStatus, "fully_validated")
	}
}

func TestParallelDiscovery_DNSSECValidFalse_Insecure(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	daneMock := NewMockDANEResolver().WithTLSA("agent.example.com", 443, TLSALookupResult{
		Found:       true,
		DNSSECValid: false,
		Records:     []TLSARecord{{Usage: 3, Selector: 0, MatchingType: 1, CertHash: "deadbeef"}},
	})

	result, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, daneMock)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v", err)
	}
	if result.DNSSECStatus != "insecure" {
		t.Errorf("DNSSECStatus = %q, want %q", result.DNSSECStatus, "insecure")
	}
}

func TestParallelDiscovery_ContextCancelled_HandlesGracefully(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	daneMock := NewMockDANEResolver().WithTLSA("agent.example.com", 443, TLSALookupResult{
		Found:       true,
		DNSSECValid: true,
		Records:     []TLSARecord{{Usage: 3, Selector: 0, MatchingType: 1, CertHash: "abc"}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	// ParallelDiscovery should not panic; it may return a result or error.
	// The mock resolvers don't check ctx, so it should still succeed.
	result, err := ParallelDiscovery(ctx, fqdn, dnsMock, daneMock)
	_ = err
	_ = result
	// We just assert no panic occurred. The mocks ignore context, so we typically
	// get a successful result here. The key is graceful handling.
}

func TestParallelDiscovery_DANEResolverReturnsError_NonFatal(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	daneMock := NewMockDANEResolver().WithError("agent.example.com", 443, errors.New("DANE lookup failed"))

	result, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, daneMock)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v (DANE failure should be non-fatal)", err)
	}
	if result == nil {
		t.Fatal("ParallelDiscovery() result is nil")
	}
	if result.AgentID != "agent-123" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "agent-123")
	}
	// TLSA lookup failed, so no records and no DNSSEC status
	if len(result.IdentityTLSA) != 0 {
		t.Errorf("IdentityTLSA length = %d, want 0", len(result.IdentityTLSA))
	}
	if result.DNSSECStatus != "" {
		t.Errorf("DNSSECStatus = %q, want empty", result.DNSSECStatus)
	}
}

func TestParallelDiscovery_TLSANotFound_NonFatal(t *testing.T) {
	fqdn, _ := models.NewFqdn("agent.example.com")

	dnsMock := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			makeDiscoveryRecord("agent-123", "https://card.example.com/card.json"),
		})

	// DANE resolver configured with no TLSA records for this FQDN
	daneMock := NewMockDANEResolver()

	result, err := ParallelDiscovery(context.Background(), fqdn, dnsMock, daneMock)
	if err != nil {
		t.Fatalf("ParallelDiscovery() unexpected error = %v", err)
	}
	if result == nil {
		t.Fatal("ParallelDiscovery() result is nil")
	}
	if result.AgentID != "agent-123" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "agent-123")
	}
	if len(result.IdentityTLSA) != 0 {
		t.Errorf("IdentityTLSA length = %d, want 0", len(result.IdentityTLSA))
	}
	if result.DNSSECStatus != "" {
		t.Errorf("DNSSECStatus = %q, want empty", result.DNSSECStatus)
	}
}

func TestParallelDiscovery_ConcurrentSafety(t *testing.T) {
	// Run ParallelDiscovery many times concurrently to check for race conditions.
	// This is most useful with -race flag.
	fqdn, _ := models.NewFqdn("agent.example.com")
	v := models.NewVersion(1, 0, 0)

	var callCount int32

	for i := 0; i < 50; i++ {
		dnsMock := NewMockDNSResolver().
			WithDiscoveryRecords("agent.example.com", []*ATIRecord{
				makeDiscoveryRecord(fmt.Sprintf("agent-%d", i), "https://card.example.com/card.json"),
			}).
			WithRecords("agent.example.com", []ATIBadgeRecord{
				{FormatVersion: "ati-badge1", URL: "https://tl.example.com/badge", Version: &v},
			})

		daneMock := NewMockDANEResolver().WithTLSA("agent.example.com", 443, TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records:     []TLSARecord{{Usage: 3, Selector: 0, MatchingType: 1, CertHash: "abc"}},
		})

		go func() {
			defer atomic.AddInt32(&callCount, 1)
			_, _ = ParallelDiscovery(context.Background(), fqdn, dnsMock, daneMock)
		}()
	}

	// Wait for all goroutines to complete (roughly)
	for atomic.LoadInt32(&callCount) < 50 {
		// busy wait briefly
	}
}
