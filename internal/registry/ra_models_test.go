package registry

import (
	"encoding/json"
	"testing"
)

func TestDescribeAgentMarketPopResult_JSON(t *testing.T) {
	result := &DescribeAgentMarketPopResult{
		RequestId:  "req-001",
		AgentHost:  "agent.example.com",
		AgentId:    "agent-001",
		Version:    "1.0.0",
		TrustLevel: "HIGH",
		Categories: []string{"dns", "security"},
		Endpoints: []MarketAgentEndpoint{
			{Host: "ep1.example.com", Port: 443, Protocol: "HTTPS", Weight: 100},
			{Host: "ep2.example.com", Port: 8443, Protocol: "HTTPS", Weight: 50},
		},
		BadgeUrl: "https://tl.example.com/badge/001",
		Mode:     "standard",
		Status:   "ACTIVE",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got DescribeAgentMarketPopResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.RequestId != result.RequestId {
		t.Errorf("RequestId = %q, want %q", got.RequestId, result.RequestId)
	}
	if got.AgentHost != result.AgentHost {
		t.Errorf("AgentHost = %q, want %q", got.AgentHost, result.AgentHost)
	}
	if got.AgentId != result.AgentId {
		t.Errorf("AgentId = %q, want %q", got.AgentId, result.AgentId)
	}
	if got.TrustLevel != result.TrustLevel {
		t.Errorf("TrustLevel = %q, want %q", got.TrustLevel, result.TrustLevel)
	}
	if got.Status != result.Status {
		t.Errorf("Status = %q, want %q", got.Status, result.Status)
	}
	if len(got.Categories) != 2 {
		t.Fatalf("Categories length = %d, want 2", len(got.Categories))
	}
	if got.Categories[0] != "dns" || got.Categories[1] != "security" {
		t.Errorf("Categories = %v, want [dns security]", got.Categories)
	}
	if len(got.Endpoints) != 2 {
		t.Fatalf("Endpoints length = %d, want 2", len(got.Endpoints))
	}
	if got.Endpoints[0].Host != "ep1.example.com" {
		t.Errorf("Endpoints[0].Host = %q", got.Endpoints[0].Host)
	}
	if got.Endpoints[0].Port != 443 {
		t.Errorf("Endpoints[0].Port = %d, want 443", got.Endpoints[0].Port)
	}
	if got.Endpoints[1].Weight != 50 {
		t.Errorf("Endpoints[1].Weight = %d, want 50", got.Endpoints[1].Weight)
	}
	if got.BadgeUrl != result.BadgeUrl {
		t.Errorf("BadgeUrl = %q, want %q", got.BadgeUrl, result.BadgeUrl)
	}
}

func TestMarketAgentEndpoint_JSON(t *testing.T) {
	ep := &MarketAgentEndpoint{
		Host:     "ep.example.com",
		Port:     8443,
		Protocol: "HTTPS",
		Weight:   75,
	}

	data, err := json.Marshal(ep)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got MarketAgentEndpoint
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.Host != ep.Host {
		t.Errorf("Host = %q, want %q", got.Host, ep.Host)
	}
	if got.Port != ep.Port {
		t.Errorf("Port = %d, want %d", got.Port, ep.Port)
	}
	if got.Protocol != ep.Protocol {
		t.Errorf("Protocol = %q, want %q", got.Protocol, ep.Protocol)
	}
	if got.Weight != ep.Weight {
		t.Errorf("Weight = %d, want %d", got.Weight, ep.Weight)
	}
}

func TestDescribeAgentMarketPopResult_EmptyFields(t *testing.T) {
	result := &DescribeAgentMarketPopResult{
		RequestId: "req-empty",
		AgentId:   "agent-empty",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got DescribeAgentMarketPopResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.AgentId != "agent-empty" {
		t.Errorf("AgentId = %q, want agent-empty", got.AgentId)
	}
	if got.TrustLevel != "" {
		t.Errorf("TrustLevel = %q, want empty", got.TrustLevel)
	}
	if got.Categories != nil {
		t.Errorf("Categories = %v, want nil", got.Categories)
	}
	if got.Endpoints != nil {
		t.Errorf("Endpoints = %v, want nil", got.Endpoints)
	}
}
