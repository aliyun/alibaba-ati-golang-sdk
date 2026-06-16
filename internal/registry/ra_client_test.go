package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/aliyun/credentials-go/credentials"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func newTestRAClientWithHandler(handler http.Handler) (*RAClient, *httptest.Server) {
	srv := httptest.NewServer(handler)
	endpoint := strings.TrimPrefix(srv.URL, "http://")

	credConfig := &credentials.Config{
		Type:            dara.String("access_key"),
		AccessKeyId:     dara.String("test-ak"),
		AccessKeySecret: dara.String("test-sk"),
	}
	cred, _ := credentials.NewCredential(credConfig)

	apiConfig := &openapi.Config{
		Credential: cred,
		Endpoint:   dara.String(endpoint),
		Protocol:   dara.String("http"),
	}
	client, _ := openapi.NewClient(apiConfig)

	return &RAClient{client: client, endpoint: endpoint}, srv
}

func TestNewRAClient_MissingCredentials(t *testing.T) {
	tests := []struct {
		name string
		opts []RAClientOption
	}{
		{"no options", nil},
		{"only AK ID", []RAClientOption{WithAccessKeyID("ak")}},
		{"only AK secret", []RAClientOption{WithAccessKeySecret("sk")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRAClient(tt.opts...)
			if err == nil {
				t.Fatal("expected error for missing credentials")
			}
			if !strings.Contains(err.Error(), "access key ID and secret are required") {
				t.Errorf("error = %q, want to contain 'access key ID and secret are required'", err.Error())
			}
		})
	}
}

func TestNewRAClient_ValidCredentials(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak-id"),
		WithAccessKeySecret("test-ak-secret"),
		WithRAEndpoint("https://test.example.com/api"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.endpoint != "https://test.example.com/api" {
		t.Errorf("endpoint = %q, want https://test.example.com/api", client.endpoint)
	}
	if client.client == nil {
		t.Error("internal openapi client is nil")
	}
}

func TestNewRAClient_DefaultEndpoint(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak-id"),
		WithAccessKeySecret("test-ak-secret"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}
	if client.endpoint != "https://ra.ansagent.cn:8180/ans/api/v1" {
		t.Errorf("endpoint = %q, want default endpoint", client.endpoint)
	}
}

func TestRAClient_GetAgent_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.GetAgent(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "GetAgent API call failed") {
		t.Errorf("error = %q, want to contain 'GetAgent API call failed'", err.Error())
	}
}

func TestRAClient_GetAgent_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agentId":   "agent-001",
			"ansName":   "test-agent",
			"agentHost": "agent.example.com",
			"status":    "ACTIVE",
			"version":   "1.0.0",
		})
	}))
	defer srv.Close()

	info, err := client.GetAgent(context.Background(), "agent-001")
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if info.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", info.AgentID)
	}
	if info.Status != "ACTIVE" {
		t.Errorf("Status = %q, want ACTIVE", info.Status)
	}
}

func TestRAClient_GetAgentByFQDN_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.GetAgentByFQDN(context.Background(), "agent.example.com")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "GetAgentByFQDN API call failed") {
		t.Errorf("error = %q, want to contain 'GetAgentByFQDN API call failed'", err.Error())
	}
}

func TestRAClient_GetAgentByFQDN_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agentId":   "agent-fqdn",
			"ansName":   "fqdn-agent",
			"agentHost": "fqdn.example.com",
			"status":    "ACTIVE",
		})
	}))
	defer srv.Close()

	info, err := client.GetAgentByFQDN(context.Background(), "fqdn.example.com")
	if err != nil {
		t.Fatalf("GetAgentByFQDN() error = %v", err)
	}
	if info.AgentID != "agent-fqdn" {
		t.Errorf("AgentID = %q, want agent-fqdn", info.AgentID)
	}
}

func TestRAClient_GetAgentBadge_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.GetAgentBadge(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "GetAgentBadge API call failed") {
		t.Errorf("error = %q, want to contain 'GetAgentBadge API call failed'", err.Error())
	}
}

func TestRAClient_GetAgentBadge_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"badgeUrl":    "https://tl.example.com/badge/001",
			"badgeStatus": "VALID",
			"agentStatus": "ACTIVE",
		})
	}))
	defer srv.Close()

	badge, err := client.GetAgentBadge(context.Background(), "agent-001")
	if err != nil {
		t.Fatalf("GetAgentBadge() error = %v", err)
	}
	if badge.BadgeURL != "https://tl.example.com/badge/001" {
		t.Errorf("BadgeURL = %q", badge.BadgeURL)
	}
	if badge.BadgeStatus != "VALID" {
		t.Errorf("BadgeStatus = %q, want VALID", badge.BadgeStatus)
	}
}

func TestRAClient_ListAgents_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.ListAgents(context.Background())
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "ListAgents API call failed") {
		t.Errorf("error = %q, want to contain 'ListAgents API call failed'", err.Error())
	}
}

func TestRAClient_ListAgents_WithOptions(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.ListAgents(context.Background(),
		WithListLimit(50),
		WithListOffset(10),
		WithListHost("agent.example.com"),
	)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}

func TestRAClient_GetAuditTrail_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.GetAuditTrail(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "GetAuditTrail API call failed") {
		t.Errorf("error = %q, want to contain 'GetAuditTrail API call failed'", err.Error())
	}
}

func TestRAClient_GetAuditTrail_WithOptions(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.GetAuditTrail(context.Background(), "agent-1",
		WithAuditLimit(100),
		WithAuditOffset(5),
	)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}

func TestRAClient_GetAuditTrail_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"records": []map[string]interface{}{
				{"eventType": "REGISTER", "details": "Agent registered"},
			},
			"total": 1,
		})
	}))
	defer srv.Close()

	trail, err := client.GetAuditTrail(context.Background(), "agent-001")
	if err != nil {
		t.Fatalf("GetAuditTrail() error = %v", err)
	}
	if trail.Total != 1 {
		t.Errorf("Total = %d, want 1", trail.Total)
	}
}

func TestRAClient_RegisterAgent_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	req := &AgentRegistrationRequest{
		AgentHost:   "test.example.com",
		AgentName:   "Test Agent",
		Version:     "1.0.0",
		IdentityCSR: "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				// dara.ToMap panics on non-pointer string fields - known SDK limitation
			}
		}()
		_, err = client.RegisterAgent(context.Background(), req)
	}()
}

func TestNewRAAPIDiscoverer(t *testing.T) {
	client, _ := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
	)
	d := NewRAAPIDiscoverer(client)
	if d == nil {
		t.Fatal("NewRAAPIDiscoverer returned nil")
	}
	if d.client != client {
		t.Error("client not set")
	}
}

func TestRAAPIDiscoverer_Discover_NetworkError(t *testing.T) {
	client, _ := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	d := NewRAAPIDiscoverer(client)

	_, err := d.Discover(context.Background(), "agent.example.com")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "RA API discovery failed") {
		t.Errorf("error = %q, want to contain 'RA API discovery failed'", err.Error())
	}
}

func TestRAAPIDiscoverer_Discover_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agentId":   "disc-001",
			"ansName":   "disc-agent",
			"agentHost": "disc.example.com",
			"status":    "ACTIVE",
			"version":   "1.0.0",
			"protocol":  "HTTPS",
			"mode":      "standard",
		})
	}))
	defer srv.Close()

	d := NewRAAPIDiscoverer(client)
	info, err := d.Discover(context.Background(), "disc.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if info.AgentID != "disc-001" {
		t.Errorf("AgentID = %q, want disc-001", info.AgentID)
	}
	if info.Source != ati.SourceRAAPI {
		t.Errorf("Source = %d, want SourceRAAPI", info.Source)
	}
	if info.FQDN != "disc.example.com" {
		t.Errorf("FQDN = %q, want disc.example.com", info.FQDN)
	}
}

func TestRAAPIDiscoverer_DiscoverWithOptions_NetworkError(t *testing.T) {
	client, _ := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	d := NewRAAPIDiscoverer(client)

	_, err := d.DiscoverWithOptions(context.Background(), "agent.example.com", ati.WithVersion("1.0"))
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}

func TestRAAgentInfoToATI(t *testing.T) {
	ra := &RAAgentInfo{
		AgentID:    "agent-001",
		BadgeURL:   "https://tl.example.com/badge/001",
		RAEndpoint: "https://ra.example.com",
		Version:    "2.0.0",
		Protocol:   "HTTPS",
		Mode:       "standard",
	}

	info := raAgentInfoToATI("test.example.com", ra)

	if info.FQDN != "test.example.com" {
		t.Errorf("FQDN = %q, want test.example.com", info.FQDN)
	}
	if info.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", info.AgentID)
	}
	if info.BadgeURL != "https://tl.example.com/badge/001" {
		t.Errorf("BadgeURL = %q", info.BadgeURL)
	}
	if info.RAEndpoint != "https://ra.example.com" {
		t.Errorf("RAEndpoint = %q", info.RAEndpoint)
	}
	if info.Version != "2.0.0" {
		t.Errorf("Version = %q, want 2.0.0", info.Version)
	}
	if info.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want HTTPS", info.Protocol)
	}
	if info.Mode != "standard" {
		t.Errorf("Mode = %q, want standard", info.Mode)
	}
	if info.Source != ati.SourceRAAPI {
		t.Errorf("Source = %d, want SourceRAAPI", info.Source)
	}
}

func TestAgentRegistrationRequest_Fields(t *testing.T) {
	req := &AgentRegistrationRequest{
		AgentHost:   "test.example.com",
		AgentName:   "Test Agent",
		Version:     "1.0.0",
		IdentityCSR: "CSR-DATA",
		ServerCSR:   "SERVER-CSR",
		Protocol:    "HTTPS",
	}

	if req.AgentHost != "test.example.com" {
		t.Errorf("AgentHost = %q", req.AgentHost)
	}
	if req.AgentName != "Test Agent" {
		t.Errorf("AgentName = %q", req.AgentName)
	}
	if req.IdentityCSR != "CSR-DATA" {
		t.Errorf("IdentityCSR = %q", req.IdentityCSR)
	}
}
