package ati

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

func newDiscoveryMock(host, agentID string) *verify.MockDNSResolver {
	return verify.NewMockDNSResolver().
		WithDiscoveryRecords(host, []*verify.ATIRecord{
			{
				ID:      agentID,
				RA:      "aliyun",
				Version: models.NewVersion(1, 0, 0),
				Mode:    verify.ATIRecordModeDirect,
			},
		})
}

func TestGetTrustCard_Success(t *testing.T) {
	tlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if want := "/tl/agents/ag-test-123/logs/latest"; r.URL.Path != want {
			t.Errorf("URL path = %q, want %q", r.URL.Path, want)
		}

		resp := models.TLResponse{
			Status:        "ACTIVE",
			SchemaVersion: "1.0",
			Payload: models.TLPayload{
				AgentID:          "ag-test-123",
				AgentName:        "test-agent",
				AgentDisplayName: "Test Agent",
				AgentHost:        "agent.example.com",
				Version:          "v1.0.0",
				AgentStatus:      "ACTIVE",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tlServer.Close()

	mockResolver := newDiscoveryMock("agent.example.com", "ag-test-123")

	ctx := context.Background()
	card, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTLBaseURL(tlServer.URL),
		withTestDNSResolver(mockResolver),
	)
	if err != nil {
		t.Fatalf("GetTrustCard() error = %v", err)
	}

	if card == nil {
		t.Fatal("GetTrustCard() returned nil")
	}
	if card.AgentID != "ag-test-123" {
		t.Errorf("AgentID = %q, want %q", card.AgentID, "ag-test-123")
	}
	if card.AgentName != "test-agent" {
		t.Errorf("AgentName = %q, want %q", card.AgentName, "test-agent")
	}
	if card.AgentDisplayName != "Test Agent" {
		t.Errorf("AgentDisplayName = %q, want %q", card.AgentDisplayName, "Test Agent")
	}
	if card.AgentHost != "agent.example.com" {
		t.Errorf("AgentHost = %q, want %q", card.AgentHost, "agent.example.com")
	}
	if card.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", card.Version, "v1.0.0")
	}
}

func TestGetTrustCard_InvalidHost(t *testing.T) {
	ctx := context.Background()
	_, err := GetTrustCard(ctx, "", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for empty host, got nil")
	}
	if want := "invalid host"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestGetTrustCard_DNSLookupFails(t *testing.T) {
	mockResolver := verify.NewMockDNSResolver()

	ctx := context.Background()
	_, err := GetTrustCard(ctx, "unknown.example.com", "v1.0.0",
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for DNS lookup failure, got nil")
	}
	if want := "failed to discover agent"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestGetTrustCard_TLServerError(t *testing.T) {
	tlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tlServer.Close()

	mockResolver := newDiscoveryMock("agent.example.com", "ag-test-123")

	ctx := context.Background()
	_, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTLBaseURL(tlServer.URL),
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for TL server error, got nil")
	}
	if want := "TL query returned status 500"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestGetTrustCard_TLServerNotFound(t *testing.T) {
	tlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tlServer.Close()

	mockResolver := newDiscoveryMock("agent.example.com", "ag-test-123")

	ctx := context.Background()
	_, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTLBaseURL(tlServer.URL),
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if want := "TL query returned status 404"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestGetTrustCard_InvalidJSON(t *testing.T) {
	tlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json{{{"))
	}))
	defer tlServer.Close()

	mockResolver := newDiscoveryMock("agent.example.com", "ag-test-123")

	ctx := context.Background()
	_, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTLBaseURL(tlServer.URL),
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if want := "failed to decode TL response"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestGetTrustCard_TLServerUnreachable(t *testing.T) {
	mockResolver := newDiscoveryMock("agent.example.com", "ag-test-123")

	ctx := context.Background()
	_, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTLBaseURL("http://127.0.0.1:1"),
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
	if want := "TL query failed"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestGetTrustCard_CancelledContext(t *testing.T) {
	tlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(models.TLResponse{})
	}))
	defer tlServer.Close()

	mockResolver := newDiscoveryMock("agent.example.com", "ag-test-123")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTLBaseURL(tlServer.URL),
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestGetTrustCard_WithDNSError(t *testing.T) {
	mockResolver := verify.NewMockDNSResolver().
		WithError("agent.example.com", &verify.DNSError{
			Type: verify.DNSErrorTimeout,
			Fqdn: "agent.example.com",
		})

	ctx := context.Background()
	_, err := GetTrustCard(ctx, "agent.example.com", "v1.0.0",
		withTestDNSResolver(mockResolver),
	)
	if err == nil {
		t.Fatal("expected error for DNS error, got nil")
	}
	if want := "failed to discover agent"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestWithTLBaseURL_Option(t *testing.T) {
	cfg := &trustCardConfig{}
	opt := withTLBaseURL("https://custom.tl.example.com")
	opt(cfg)
	if cfg.tlBaseURL != "https://custom.tl.example.com" {
		t.Errorf("tlBaseURL = %q, want %q", cfg.tlBaseURL, "https://custom.tl.example.com")
	}
}

func TestResolveAgentID_NoRecords(t *testing.T) {
	mockResolver := verify.NewMockDNSResolver()
	fqdn, err := models.NewFqdn("norecords.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx := context.Background()
	_, err = resolveAgentID(ctx, mockResolver, fqdn)
	if err == nil {
		t.Fatal("expected error for no records, got nil")
	}
	if want := "no _ati records found"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want to contain %q", err.Error(), want)
	}
}

func TestResolveAgentID_WithRecords(t *testing.T) {
	mockResolver := newDiscoveryMock("agent.example.com", "ag-real-id")

	fqdn, err := models.NewFqdn("agent.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx := context.Background()
	agentID, err := resolveAgentID(ctx, mockResolver, fqdn)
	if err != nil {
		t.Fatalf("resolveAgentID() error = %v", err)
	}
	if agentID != "ag-real-id" {
		t.Errorf("agentID = %q, want %q", agentID, "ag-real-id")
	}
}

func withTestDNSResolver(resolver verify.DNSResolver) TrustCardOption {
	return func(c *trustCardConfig) {
		c.dnsResolver = resolver
	}
}
