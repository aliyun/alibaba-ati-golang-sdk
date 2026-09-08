package verify

import (
	"context"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestStandardDNSResolver_WithServerAddress(t *testing.T) {
	r := NewStandardDNSResolver()
	r.WithServerAddress("1.1.1.1:53")

	if r.resolver == nil {
		t.Fatal("resolver should not be nil after WithServerAddress")
	}
}

func TestStandardDNSResolver_WithServerAddress_NoPort(t *testing.T) {
	r := NewStandardDNSResolver()
	r.WithServerAddress("8.8.8.8")

	if r.resolver == nil {
		t.Fatal("resolver should not be nil after WithServerAddress without port")
	}
}

func TestStandardDNSResolver_WithServerAddress_EmptyString(t *testing.T) {
	r := NewStandardDNSResolver()
	original := r.resolver
	r.WithServerAddress("")

	if r.resolver != original {
		t.Error("resolver should not change with empty address")
	}
}

func TestStandardDNSResolver_LookupATIBadge_CacheHit(t *testing.T) {
	r := NewStandardDNSResolver()
	fqdn, _ := models.NewFqdn("agent.example.com")

	// Seed the cache
	cacheKey := "badge:" + fqdn.String()
	cachedResult := DNSLookupResult{
		Found:   true,
		Records: []ATIBadgeRecord{{URL: "https://cached.example.com"}},
	}
	r.setCache(cacheKey, cachedResult)

	// Should hit cache
	result, err := r.LookupATIBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIBadge cache hit error: %v", err)
	}
	if !result.Found {
		t.Error("expected Found=true from cache")
	}
	if len(result.Records) != 1 || result.Records[0].URL != "https://cached.example.com" {
		t.Errorf("unexpected cached result: %+v", result)
	}
}

func TestStandardDNSResolver_FindPreferredBadge_SortVersions(t *testing.T) {
	r := NewStandardDNSResolver()
	r.WithTimeout(200 * time.Millisecond)
	fqdn, _ := models.NewFqdn("sort-test.example.com")

	// Seed cache with badge records that include nil and non-nil versions
	cacheKey := "badge:" + fqdn.String()
	v1 := models.NewVersion(1, 0, 0)
	v2 := models.NewVersion(2, 0, 0)
	cachedResult := DNSLookupResult{
		Found: true,
		Records: []ATIBadgeRecord{
			{URL: "https://v1.example.com", Version: &v1},
			{URL: "https://nil.example.com", Version: nil},
			{URL: "https://v2.example.com", Version: &v2},
		},
	}
	r.setCache(cacheKey, cachedResult)

	// FindPreferredBadge should return the newest version (v2)
	record, err := r.FindPreferredBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("FindPreferredBadge error: %v", err)
	}
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if record.URL != "https://v2.example.com" {
		t.Errorf("expected v2 record (newest), got: %s", record.URL)
	}
}

func TestStandardDNSResolver_FindPreferredBadge_AllNilVersions(t *testing.T) {
	r := NewStandardDNSResolver()
	fqdn, _ := models.NewFqdn("nil-versions.example.com")

	// Seed cache with badge records that all have nil versions
	cacheKey := "badge:" + fqdn.String()
	cachedResult := DNSLookupResult{
		Found: true,
		Records: []ATIBadgeRecord{
			{URL: "https://first.example.com", Version: nil},
			{URL: "https://second.example.com", Version: nil},
		},
	}
	r.setCache(cacheKey, cachedResult)

	record, err := r.FindPreferredBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("FindPreferredBadge error: %v", err)
	}
	if record == nil {
		t.Fatal("expected non-nil record")
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_CacheHit(t *testing.T) {
	r := NewStandardDNSResolver()
	fqdn, _ := models.NewFqdn("discovery-cache.example.com")

	// Seed the cache
	cacheKey := "discovery:" + fqdn.String()
	cachedResult := ATIDiscoveryResult{
		Found: true,
		Records: []*ATIRecord{
			{ID: "ag-cached", RA: "aliyun"},
		},
	}
	r.setCache(cacheKey, cachedResult)

	// Should hit cache
	result, err := r.LookupATIDiscovery(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIDiscovery cache hit error: %v", err)
	}
	if !result.Found {
		t.Error("expected Found=true from cache")
	}
	if len(result.Records) != 1 || result.Records[0].ID != "ag-cached" {
		t.Errorf("unexpected cached result: %+v", result)
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_DNSError(t *testing.T) {
	// Use localhost port that definitely won't have a DNS server
	r := NewStandardDNSResolver()
	r.WithServerAddress("127.0.0.1:19")
	r.WithTimeout(200 * time.Millisecond)

	fqdn, _ := models.NewFqdn("error.example.com")

	_, err := r.LookupATIDiscovery(context.Background(), fqdn)
	if err == nil {
		t.Fatal("expected error for unreachable DNS server")
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_NotFound(t *testing.T) {
	// This test requires a working DNS server that returns NXDOMAIN
	// We'll use a very short timeout against a known non-existent domain
	r := NewStandardDNSResolver()
	r.WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("this-domain-definitely-does-not-exist-12345.invalid")

	result, err := r.LookupATIDiscovery(context.Background(), fqdn)
	// Either error or NotFound is acceptable
	if err == nil && result.Found {
		t.Error("expected not-found for non-existent domain")
	}
}

func TestStandardDNSResolver_GetCached_Expired(t *testing.T) {
	r := NewStandardDNSResolver()
	r.WithCacheTTL(1 * time.Millisecond) // very short TTL

	// Set cache
	r.setCache("test-key", "test-value")

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// Should return nil (expired)
	result, ok := r.getCached("test-key")
	if ok {
		t.Errorf("expected cache miss after TTL, got: %v", result)
	}
}
