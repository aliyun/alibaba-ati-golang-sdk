package ati

import (
	"context"
	"testing"
)

func TestDiscoverySource_Constants(t *testing.T) {
	if SourceDNS != 0 {
		t.Errorf("SourceDNS = %d, want 0", SourceDNS)
	}
	if SourceRAAPI != 1 {
		t.Errorf("SourceRAAPI = %d, want 1", SourceRAAPI)
	}
}

func TestAgentInfo_Fields(t *testing.T) {
	info := &AgentInfo{
		FQDN:       "agent.example.com",
		AgentID:    "agent-123",
		BadgeURL:   "https://tl.example.com/badge/123",
		RAEndpoint: "https://ra.example.com",
		Endpoints: []AgentEndpoint{
			{Host: "ep1.example.com", Port: 443, Protocol: "HTTPS"},
			{Host: "ep2.example.com", Port: 8443, Protocol: "HTTPS"},
		},
		TrustLevel: "HIGH",
		Categories: []string{"dns", "security"},
		Version:    "1.0.0",
		Protocol:   "HTTPS",
		Mode:       "standard",
		Source:     SourceRAAPI,
	}
	if info.FQDN != "agent.example.com" {
		t.Errorf("FQDN = %s", info.FQDN)
	}
	if info.AgentID != "agent-123" {
		t.Errorf("AgentID = %s", info.AgentID)
	}
	if info.Source != SourceRAAPI {
		t.Errorf("Source = %d, want SourceRAAPI", info.Source)
	}
	if info.TrustLevel != "HIGH" {
		t.Errorf("TrustLevel = %q, want HIGH", info.TrustLevel)
	}
	if len(info.Categories) != 2 {
		t.Fatalf("Categories length = %d, want 2", len(info.Categories))
	}
	if info.Categories[0] != "dns" {
		t.Errorf("Categories[0] = %q, want dns", info.Categories[0])
	}
	if len(info.Endpoints) != 2 {
		t.Fatalf("Endpoints length = %d, want 2", len(info.Endpoints))
	}
	if info.Endpoints[0].Host != "ep1.example.com" {
		t.Errorf("Endpoints[0].Host = %q", info.Endpoints[0].Host)
	}
	if info.Endpoints[0].Port != 443 {
		t.Errorf("Endpoints[0].Port = %d, want 443", info.Endpoints[0].Port)
	}
	if info.Endpoints[1].Port != 8443 {
		t.Errorf("Endpoints[1].Port = %d, want 8443", info.Endpoints[1].Port)
	}
}

func TestAgentEndpoint_Fields(t *testing.T) {
	ep := AgentEndpoint{
		Host:     "ep.example.com",
		Port:     8443,
		Protocol: "HTTPS",
	}
	if ep.Host != "ep.example.com" {
		t.Errorf("Host = %q", ep.Host)
	}
	if ep.Port != 8443 {
		t.Errorf("Port = %d, want 8443", ep.Port)
	}
	if ep.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want HTTPS", ep.Protocol)
	}
}

func TestDiscoverOption_WithVersion(t *testing.T) {
	cfg := &discoverConfig{}
	WithVersion("2.0.0")(cfg)
	if cfg.version != "2.0.0" {
		t.Errorf("version = %s, want 2.0.0", cfg.version)
	}
}

func TestDiscoverOption_WithProtocol(t *testing.T) {
	cfg := &discoverConfig{}
	WithProtocol("HTTPS")(cfg)
	if cfg.protocol != "HTTPS" {
		t.Errorf("protocol = %s, want HTTPS", cfg.protocol)
	}
}

func TestDiscoverOption_WithSource(t *testing.T) {
	cfg := &discoverConfig{}
	WithSource(SourceDNS)(cfg)
	if cfg.source == nil {
		t.Fatal("source is nil")
	}
	if *cfg.source != SourceDNS {
		t.Errorf("source = %d, want SourceDNS", *cfg.source)
	}
}

func TestResolveDiscoverOptions(t *testing.T) {
	version, protocol := ResolveDiscoverOptions(
		WithVersion(">=1.0.0"),
		WithProtocol("HTTPS"),
	)
	if version != ">=1.0.0" {
		t.Errorf("version = %q, want >=1.0.0", version)
	}
	if protocol != "HTTPS" {
		t.Errorf("protocol = %q, want HTTPS", protocol)
	}
}

func TestResolveDiscoverOptions_Empty(t *testing.T) {
	version, protocol := ResolveDiscoverOptions()
	if version != "" {
		t.Errorf("version = %q, want empty", version)
	}
	if protocol != "" {
		t.Errorf("protocol = %q, want empty", protocol)
	}
}

func TestAgentDiscoverer_Interface(t *testing.T) {
	var d AgentDiscoverer = &mockDiscoverer{
		info: &AgentInfo{FQDN: "test.example.com"},
	}
	info, err := d.Discover(context.Background(), "test.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if info.FQDN != "test.example.com" {
		t.Errorf("FQDN = %s, want test.example.com", info.FQDN)
	}
}
