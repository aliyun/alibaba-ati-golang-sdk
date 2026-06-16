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
