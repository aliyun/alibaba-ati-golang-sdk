package ati

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// newConnectTestClient builds a minimal AgentClient with only a mock DNS resolver,
// bypassing the cert-loading in NewAgentClient. This is sufficient because Connect
// only uses the dnsResolver field.
func newConnectTestClient(resolver verify.DNSResolver) *AgentClient {
	return &AgentClient{
		dnsResolver: resolver,
	}
}

func TestConnect_EmptyTarget(t *testing.T) {
	client := newConnectTestClient(verify.NewMockDNSResolver())

	_, err := client.Connect(context.Background(), ConnectRequest{Target: ""})
	if err == nil {
		t.Fatal("Connect() expected error for empty target, got nil")
	}
	if !strings.Contains(err.Error(), "target is required") {
		t.Errorf("Connect() error = %q, want to contain %q", err.Error(), "target is required")
	}
}

func TestConnect_InvalidTarget(t *testing.T) {
	client := newConnectTestClient(verify.NewMockDNSResolver())

	// Targets with invalid characters or labels that start/end with hyphen
	invalidTargets := []string{
		"-invalid.example.com", // label starts with hyphen
		"invalid-.example.com", // label ends with hyphen
		"_invalid.example.com", // underscore is not a valid label character
		"example..com",         // empty label
	}
	for _, target := range invalidTargets {
		t.Run(target, func(t *testing.T) {
			_, err := client.Connect(context.Background(), ConnectRequest{Target: target})
			if err == nil {
				t.Fatalf("Connect() expected error for invalid target %q, got nil", target)
			}
			if !strings.Contains(err.Error(), "invalid target") {
				t.Errorf("Connect() error = %q, want to contain %q", err.Error(), "invalid target")
			}
		})
	}
}

func TestConnect_DNSLookupFails(t *testing.T) {
	host := "fail.example.com"
	mock := verify.NewMockDNSResolver().
		WithError(host, errors.New("DNS lookup failed"))

	client := newConnectTestClient(mock)

	_, err := client.Connect(context.Background(), ConnectRequest{Target: host})
	if err == nil {
		t.Fatal("Connect() expected error for DNS lookup failure, got nil")
	}
	if !strings.Contains(err.Error(), "DNS validation failed") {
		t.Errorf("Connect() error = %q, want to contain %q", err.Error(), "DNS validation failed")
	}
}

func TestConnect_DNSNotFound(t *testing.T) {
	host := "notfound.example.com"
	// MockDNSResolver with no records configured returns Found=false with no error.
	mock := verify.NewMockDNSResolver()

	client := newConnectTestClient(mock)

	_, err := client.Connect(context.Background(), ConnectRequest{Target: host})
	if err == nil {
		t.Fatal("Connect() expected error for no _ati record, got nil")
	}
	if !strings.Contains(err.Error(), "no _ati record") {
		t.Errorf("Connect() error = %q, want to contain %q", err.Error(), "no _ati record")
	}
}

func TestConnect_DNSEmptyRecords(t *testing.T) {
	host := "empty.example.com"
	// WithDiscoveryRecords with nil/empty slice still produces Found=false in the mock
	// because the mock checks len(records) > 0.
	mock := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, nil)

	client := newConnectTestClient(mock)

	_, err := client.Connect(context.Background(), ConnectRequest{Target: host})
	if err == nil {
		t.Fatal("Connect() expected error for empty records, got nil")
	}
	if !strings.Contains(err.Error(), "no _ati record") {
		t.Errorf("Connect() error = %q, want to contain %q", err.Error(), "no _ati record")
	}
}

func TestConnect_Success(t *testing.T) {
	host := "agent.example.com"
	agentID := "ag-success-123"
	mock := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{
				ID:      agentID,
				RA:      "aliyun",
				Version: models.NewVersion(1, 0, 0),
				Mode:    verify.ATIRecordModeDirect,
			},
		})

	client := newConnectTestClient(mock)

	result, err := client.Connect(context.Background(), ConnectRequest{Target: host})
	if err != nil {
		t.Fatalf("Connect() unexpected error = %v", err)
	}
	if result == nil {
		t.Fatal("Connect() returned nil result")
	}
	if result.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", result.AgentID, agentID)
	}
	wantEndpoint := "https://" + host
	if result.Endpoint != wantEndpoint {
		t.Errorf("Endpoint = %q, want %q", result.Endpoint, wantEndpoint)
	}
}

func TestConnect_Success_WithVersion(t *testing.T) {
	host := "versioned.example.com"
	agentID := "ag-versioned-456"
	mock := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{
				ID:      agentID,
				RA:      "aliyun",
				Version: models.NewVersion(2, 0, 0),
				Mode:    verify.ATIRecordModeDirect,
			},
		})

	client := newConnectTestClient(mock)

	result, err := client.Connect(context.Background(), ConnectRequest{
		Target:  host,
		Version: "v2.0.0",
	})
	if err != nil {
		t.Fatalf("Connect() unexpected error = %v", err)
	}
	if result == nil {
		t.Fatal("Connect() returned nil result")
	}
	if result.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", result.AgentID, agentID)
	}
	if result.Endpoint != "https://"+host {
		t.Errorf("Endpoint = %q, want %q", result.Endpoint, "https://"+host)
	}
}

func TestConnect_Success_MultipleRecords(t *testing.T) {
	host := "multi.example.com"
	agentID := "ag-multi-789"
	mock := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{
				ID:      agentID,
				RA:      "aliyun",
				Version: models.NewVersion(1, 0, 0),
				Mode:    verify.ATIRecordModeDirect,
			},
			{
				ID:      "ag-other",
				RA:      "aliyun",
				Version: models.NewVersion(2, 0, 0),
				Mode:    verify.ATIRecordModeDirect,
			},
		})

	client := newConnectTestClient(mock)

	result, err := client.Connect(context.Background(), ConnectRequest{Target: host})
	if err != nil {
		t.Fatalf("Connect() unexpected error = %v", err)
	}
	if result == nil {
		t.Fatal("Connect() returned nil result")
	}
	// The first record's ID should be used
	if result.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q (first record)", result.AgentID, agentID)
	}
}

func TestConnect_ContextCancelled(t *testing.T) {
	host := "cancelled.example.com"
	mock := verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{
				ID:      "ag-cancel",
				RA:      "aliyun",
				Version: models.NewVersion(1, 0, 0),
				Mode:    verify.ATIRecordModeDirect,
			},
		})

	client := newConnectTestClient(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// The mock ignores context, so the lookup will still succeed.
	// This test verifies the function can be called with a cancelled context.
	result, err := client.Connect(ctx, ConnectRequest{Target: host})
	// MockDNSResolver ignores context, so we still expect success.
	if err != nil {
		// If an error occurs, it should be a context error, not a DNS error.
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() unexpected non-context error = %v", err)
		}
		return
	}
	if result == nil {
		t.Fatal("Connect() returned nil result with cancelled context")
	}
}
