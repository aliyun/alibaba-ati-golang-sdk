package verify

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestMockDNSResolver_LookupATIDiscovery_Found(t *testing.T) {
	record := &ATIRecord{
		ID:       "ag-123",
		RA:       "aliyun",
		Version:  models.NewVersion(1, 0, 0),
		Mode:     ATIRecordModeDirect,
		Protocol: "mcp",
	}

	mock := NewMockDNSResolver().
		WithDiscoveryRecords("test.example.com", []*ATIRecord{record})

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := mock.LookupATIDiscovery(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIDiscovery() error = %v", err)
	}
	if !result.Found {
		t.Fatal("LookupATIDiscovery() Found = false, want true")
	}
	if len(result.Records) != 1 {
		t.Fatalf("LookupATIDiscovery() Records = %d, want 1", len(result.Records))
	}
	if result.Records[0].ID != "ag-123" {
		t.Errorf("ID = %q, want %q", result.Records[0].ID, "ag-123")
	}
}

func TestMockDNSResolver_LookupATIDiscovery_NotFound(t *testing.T) {
	mock := NewMockDNSResolver()
	fqdn, _ := models.NewFqdn("unknown.example.com")
	result, err := mock.LookupATIDiscovery(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIDiscovery() error = %v", err)
	}
	if result.Found {
		t.Error("LookupATIDiscovery() Found = true, want false")
	}
}

func TestMockDNSResolver_LookupATIDiscovery_Error(t *testing.T) {
	mock := NewMockDNSResolver().
		WithError("test.example.com", &DNSError{Type: DNSErrorTimeout, Fqdn: "test.example.com"})

	fqdn, _ := models.NewFqdn("test.example.com")
	_, err := mock.LookupATIDiscovery(context.Background(), fqdn)
	if err == nil {
		t.Fatal("LookupATIDiscovery() expected error, got nil")
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_Found(t *testing.T) {
	addr := startFakeDNSForDiscovery(t, map[string][]string{
		"_ati.test.example.com.": {
			"v=ati1; id=ag-abc; ra=aliyun; version=v1.0.0; mode=direct",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := r.LookupATIDiscovery(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIDiscovery() error = %v", err)
	}
	if !result.Found {
		t.Fatal("LookupATIDiscovery() Found = false, want true")
	}
	if len(result.Records) != 1 {
		t.Fatalf("Records length = %d, want 1", len(result.Records))
	}
	if result.Records[0].ID != "ag-abc" {
		t.Errorf("ID = %q, want %q", result.Records[0].ID, "ag-abc")
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_NotFound(t *testing.T) {
	addr := startFakeDNSForDiscovery(t, map[string][]string{})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("nonexistent.example.com")
	result, err := r.LookupATIDiscovery(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIDiscovery() error = %v", err)
	}
	if result.Found {
		t.Error("LookupATIDiscovery() Found = true, want false")
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_UnparseableRecords(t *testing.T) {
	addr := startFakeDNSForDiscovery(t, map[string][]string{
		"_ati.test.example.com.": {
			"this is not a valid ati record",
			"v=ati2; completely wrong format",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := r.LookupATIDiscovery(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupATIDiscovery() error = %v", err)
	}
	if result.Found {
		t.Error("LookupATIDiscovery() Found = true, want false (all records unparseable)")
	}
}

func TestStandardDNSResolver_LookupATIDiscovery_HardError(t *testing.T) {
	// Use an address that can't be reached to cause a hard error
	r := NewStandardDNSResolver().
		WithResolver(&net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: &net.DNSError{Err: "server failure", IsTimeout: false}}
			},
		}).
		WithTimeout(1 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	_, err := r.LookupATIDiscovery(context.Background(), fqdn)
	if err == nil {
		t.Fatal("LookupATIDiscovery() expected error for hard failure")
	}
}

// startFakeDNSForDiscovery reuses the startFakeDNS helper from dns_resolver_integration_test.go.
// Since it's in the same package, we can reuse it directly.
func startFakeDNSForDiscovery(t *testing.T, records map[string][]string) string {
	t.Helper()
	return startFakeDNS(t, records)
}
