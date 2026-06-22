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
		WithRAEndpoint("alidns.cn-hangzhou.aliyuncs.com"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.endpoint != "alidns.cn-hangzhou.aliyuncs.com" {
		t.Errorf("endpoint = %q, want alidns.cn-hangzhou.aliyuncs.com", client.endpoint)
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
	if client.endpoint != "alidns.aliyuncs.com" {
		t.Errorf("endpoint = %q, want alidns.aliyuncs.com", client.endpoint)
	}
}

func TestRAClient_DescribeAgentRegisterInfoMarket_NetworkError(t *testing.T) {
	client, err := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	if err != nil {
		t.Fatalf("NewRAClient() error = %v", err)
	}

	_, err = client.DescribeAgentRegisterInfoMarket(context.Background(), "agent.example.com", "")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "DescribeAgentRegisterInfoMarket API call failed") {
		t.Errorf("error = %q, want to contain 'DescribeAgentRegisterInfoMarket API call failed'", err.Error())
	}
}

func TestRAClient_DescribeAgentRegisterInfoMarket_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"RequestId":  "test-req-001",
			"AgentHost":  "agent.example.com",
			"AgentId":    "agent-001",
			"Version":    "1.2.0",
			"TrustLevel": "HIGH",
			"Categories": []string{"dns", "security"},
			"Endpoints": []map[string]interface{}{
				{"Host": "ep1.example.com", "Port": 443, "Protocol": "HTTPS", "Weight": 100},
			},
			"BadgeUrl": "https://tl.example.com/badge/001",
			"Mode":     "standard",
			"Status":   "ACTIVE",
		})
	}))
	defer srv.Close()

	result, err := client.DescribeAgentRegisterInfoMarket(context.Background(), "agent.example.com", ">=1.0.0")
	if err != nil {
		t.Fatalf("DescribeAgentRegisterInfoMarket() error = %v", err)
	}
	if result.AgentId != "agent-001" {
		t.Errorf("AgentId = %q, want agent-001", result.AgentId)
	}
	if result.TrustLevel != "HIGH" {
		t.Errorf("TrustLevel = %q, want HIGH", result.TrustLevel)
	}
	if result.Status != "ACTIVE" {
		t.Errorf("Status = %q, want ACTIVE", result.Status)
	}
	if len(result.Endpoints) != 1 {
		t.Fatalf("Endpoints length = %d, want 1", len(result.Endpoints))
	}
	if result.Endpoints[0].Host != "ep1.example.com" {
		t.Errorf("Endpoints[0].Host = %q, want ep1.example.com", result.Endpoints[0].Host)
	}
	if result.Endpoints[0].Port != 443 {
		t.Errorf("Endpoints[0].Port = %d, want 443", result.Endpoints[0].Port)
	}
	if result.BadgeUrl != "https://tl.example.com/badge/001" {
		t.Errorf("BadgeUrl = %q", result.BadgeUrl)
	}
	if len(result.Categories) != 2 || result.Categories[0] != "dns" {
		t.Errorf("Categories = %v, want [dns security]", result.Categories)
	}
}

func TestRAClient_DescribeAgentRegisterInfoMarket_EmptyVersion(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"RequestId": "test-req-002",
			"AgentHost": "agent.example.com",
			"AgentId":   "agent-002",
			"Status":    "ACTIVE",
		})
	}))
	defer srv.Close()

	result, err := client.DescribeAgentRegisterInfoMarket(context.Background(), "agent.example.com", "")
	if err != nil {
		t.Fatalf("DescribeAgentRegisterInfoMarket() error = %v", err)
	}
	if result.AgentId != "agent-002" {
		t.Errorf("AgentId = %q, want agent-002", result.AgentId)
	}
}

func TestRAClient_DescribeAgentRegisterInfoMarket_MultipleEndpoints(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"RequestId": "test-req-003",
			"AgentHost": "multi.example.com",
			"AgentId":   "agent-003",
			"Endpoints": []map[string]interface{}{
				{"Host": "ep1.example.com", "Port": 443, "Protocol": "HTTPS", "Weight": 70},
				{"Host": "ep2.example.com", "Port": 8443, "Protocol": "HTTPS", "Weight": 30},
			},
			"Status": "ACTIVE",
		})
	}))
	defer srv.Close()

	result, err := client.DescribeAgentRegisterInfoMarket(context.Background(), "multi.example.com", "")
	if err != nil {
		t.Fatalf("DescribeAgentRegisterInfoMarket() error = %v", err)
	}
	if len(result.Endpoints) != 2 {
		t.Fatalf("Endpoints length = %d, want 2", len(result.Endpoints))
	}
	if result.Endpoints[1].Port != 8443 {
		t.Errorf("Endpoints[1].Port = %d, want 8443", result.Endpoints[1].Port)
	}
	if result.Endpoints[0].Weight != 70 {
		t.Errorf("Endpoints[0].Weight = %d, want 70", result.Endpoints[0].Weight)
	}
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
			"RequestId":  "disc-req-001",
			"AgentHost":  "disc.example.com",
			"AgentId":    "disc-001",
			"Version":    "1.0.0",
			"TrustLevel": "MEDIUM",
			"Categories": []string{"dns"},
			"Endpoints": []map[string]interface{}{
				{"Host": "ep.disc.example.com", "Port": 443, "Protocol": "HTTPS", "Weight": 100},
			},
			"BadgeUrl": "https://tl.example.com/badge/disc",
			"Mode":     "standard",
			"Status":   "ACTIVE",
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
	if info.TrustLevel != "MEDIUM" {
		t.Errorf("TrustLevel = %q, want MEDIUM", info.TrustLevel)
	}
	if len(info.Endpoints) != 1 {
		t.Fatalf("Endpoints length = %d, want 1", len(info.Endpoints))
	}
	if info.Endpoints[0].Host != "ep.disc.example.com" {
		t.Errorf("Endpoints[0].Host = %q, want ep.disc.example.com", info.Endpoints[0].Host)
	}
	if info.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want HTTPS", info.Protocol)
	}
}

func TestRAAPIDiscoverer_DiscoverWithOptions_NetworkError(t *testing.T) {
	client, _ := NewRAClient(
		WithAccessKeyID("test-ak"),
		WithAccessKeySecret("test-sk"),
		WithRAEndpoint("https://nonexistent.invalid:19999"),
	)
	d := NewRAAPIDiscoverer(client)

	_, err := d.DiscoverWithOptions(context.Background(), "agent.example.com", ati.WithVersion(">=1.0"))
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}

func TestRAAPIDiscoverer_DiscoverWithOptions_Success(t *testing.T) {
	client, srv := newTestRAClientWithHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"RequestId": "disc-req-002",
			"AgentHost": "opts.example.com",
			"AgentId":   "opts-001",
			"Version":   "2.0.0",
			"Endpoints": []map[string]interface{}{
				{"Host": "ep.opts.example.com", "Port": 443, "Protocol": "HTTPS", "Weight": 100},
			},
			"Status": "ACTIVE",
		})
	}))
	defer srv.Close()

	d := NewRAAPIDiscoverer(client)
	info, err := d.DiscoverWithOptions(context.Background(), "opts.example.com", ati.WithVersion(">=2.0.0"))
	if err != nil {
		t.Fatalf("DiscoverWithOptions() error = %v", err)
	}
	if info.AgentID != "opts-001" {
		t.Errorf("AgentID = %q, want opts-001", info.AgentID)
	}
	if info.Version != "2.0.0" {
		t.Errorf("Version = %q, want 2.0.0", info.Version)
	}
}

func TestMarketResultToATI(t *testing.T) {
	result := &DescribeAgentMarketPopResult{
		AgentId:    "agent-001",
		BadgeUrl:   "https://tl.example.com/badge/001",
		Version:    "2.0.0",
		TrustLevel: "HIGH",
		Categories: []string{"dns", "security"},
		Mode:       "standard",
		Endpoints: []MarketAgentEndpoint{
			{Host: "ep1.example.com", Port: 443, Protocol: "HTTPS", Weight: 100},
		},
	}

	info := marketResultToATI("test.example.com", result)

	if info.FQDN != "test.example.com" {
		t.Errorf("FQDN = %q, want test.example.com", info.FQDN)
	}
	if info.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", info.AgentID)
	}
	if info.BadgeURL != "https://tl.example.com/badge/001" {
		t.Errorf("BadgeURL = %q", info.BadgeURL)
	}
	if info.TrustLevel != "HIGH" {
		t.Errorf("TrustLevel = %q, want HIGH", info.TrustLevel)
	}
	if len(info.Categories) != 2 {
		t.Fatalf("Categories length = %d, want 2", len(info.Categories))
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
	if len(info.Endpoints) != 1 {
		t.Fatalf("Endpoints length = %d, want 1", len(info.Endpoints))
	}
	if info.Endpoints[0].Host != "ep1.example.com" {
		t.Errorf("Endpoints[0].Host = %q", info.Endpoints[0].Host)
	}
	if info.Endpoints[0].Port != 443 {
		t.Errorf("Endpoints[0].Port = %d, want 443", info.Endpoints[0].Port)
	}
}

func TestMarketResultToATI_NoEndpoints(t *testing.T) {
	result := &DescribeAgentMarketPopResult{
		AgentId: "agent-empty",
		Version: "1.0.0",
	}

	info := marketResultToATI("empty.example.com", result)

	if info.Protocol != "" {
		t.Errorf("Protocol = %q, want empty when no endpoints", info.Protocol)
	}
	if len(info.Endpoints) != 0 {
		t.Errorf("Endpoints length = %d, want 0", len(info.Endpoints))
	}
}
