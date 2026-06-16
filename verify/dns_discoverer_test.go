package verify

import (
	"context"
	"errors"
	"testing"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/models"
)

func TestNewDNSDiscoverer(t *testing.T) {
	resolver := NewMockDNSResolver()
	d := NewDNSDiscoverer(resolver)
	if d == nil {
		t.Fatal("NewDNSDiscoverer returned nil")
	}
	if d.resolver != resolver {
		t.Error("resolver not set")
	}
}

func TestDNSDiscoverer_Discover_FullRecords(t *testing.T) {
	resolver := NewMockDNSResolver()

	v, _ := models.ParseVersion("1.0.0")
	resolver.WithDiscoveryRecords("agent.example.com", []*ATIRecord{
		{
			FormatVersion: "ati1",
			AgentID:       "agent-001",
			RAEndpoint:    "https://ra.example.com",
			Version:       "1.0.0",
			Protocol:      "HTTPS",
			Mode:          "standard",
		},
	})
	resolver.WithRecords("agent.example.com", []ATIBadgeRecord{
		{
			FormatVersion: "ati-badge1",
			URL:           "https://tl.example.com/badge/001",
			Version:       &v,
		},
	})

	d := NewDNSDiscoverer(resolver)
	info, err := d.Discover(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if info.FQDN != "agent.example.com" {
		t.Errorf("FQDN = %q, want agent.example.com", info.FQDN)
	}
	if info.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", info.AgentID)
	}
	if info.RAEndpoint != "https://ra.example.com" {
		t.Errorf("RAEndpoint = %q", info.RAEndpoint)
	}
	if info.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", info.Version)
	}
	if info.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want HTTPS", info.Protocol)
	}
	if info.Mode != "standard" {
		t.Errorf("Mode = %q, want standard", info.Mode)
	}
	if info.BadgeURL != "https://tl.example.com/badge/001" {
		t.Errorf("BadgeURL = %q", info.BadgeURL)
	}
	if info.Source != ati.SourceDNS {
		t.Errorf("Source = %d, want SourceDNS", info.Source)
	}
}

func TestDNSDiscoverer_Discover_BadgeOnly(t *testing.T) {
	resolver := NewMockDNSResolver()
	resolver.WithRecords("badge-only.example.com", []ATIBadgeRecord{
		{
			FormatVersion: "ati-badge1",
			URL:           "https://tl.example.com/badge/002",
		},
	})

	d := NewDNSDiscoverer(resolver)
	info, err := d.Discover(context.Background(), "badge-only.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if info.AgentID != "" {
		t.Errorf("AgentID = %q, want empty", info.AgentID)
	}
	if info.BadgeURL != "https://tl.example.com/badge/002" {
		t.Errorf("BadgeURL = %q", info.BadgeURL)
	}
}

func TestDNSDiscoverer_Discover_VersionFromBadge(t *testing.T) {
	resolver := NewMockDNSResolver()

	resolver.WithDiscoveryRecords("v-from-badge.example.com", []*ATIRecord{
		{
			FormatVersion: "ati1",
			AgentID:       "agent-v",
		},
	})

	v, _ := models.ParseVersion("2.0.0")
	resolver.WithRecords("v-from-badge.example.com", []ATIBadgeRecord{
		{
			FormatVersion: "ati-badge1",
			URL:           "https://tl.example.com/badge/v",
			Version:       &v,
		},
	})

	d := NewDNSDiscoverer(resolver)
	info, err := d.Discover(context.Background(), "v-from-badge.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if info.Version != "v2.0.0" {
		t.Errorf("Version = %q, want v2.0.0 (from badge)", info.Version)
	}
}

func TestDNSDiscoverer_Discover_NoRecords(t *testing.T) {
	resolver := NewMockDNSResolver()
	d := NewDNSDiscoverer(resolver)

	_, err := d.Discover(context.Background(), "norecords.example.com")
	if err == nil {
		t.Fatal("expected error for no records")
	}
}

func TestDNSDiscoverer_Discover_InvalidFQDN(t *testing.T) {
	resolver := NewMockDNSResolver()
	d := NewDNSDiscoverer(resolver)

	_, err := d.Discover(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty FQDN")
	}
}

func TestDNSDiscoverer_Discover_BadgeLookupError(t *testing.T) {
	resolver := NewMockDNSResolver()
	resolver.WithError("error.example.com", errors.New("dns timeout"))

	d := NewDNSDiscoverer(resolver)
	_, err := d.Discover(context.Background(), "error.example.com")
	if err == nil {
		t.Fatal("expected error for badge lookup failure")
	}
}

func TestDNSDiscoverer_DiscoverWithOptions(t *testing.T) {
	resolver := NewMockDNSResolver()
	resolver.WithRecords("opts.example.com", []ATIBadgeRecord{
		{
			FormatVersion: "ati-badge1",
			URL:           "https://tl.example.com/badge/opts",
		},
	})

	d := NewDNSDiscoverer(resolver)
	info, err := d.DiscoverWithOptions(context.Background(), "opts.example.com", ati.WithVersion("1.0"))
	if err != nil {
		t.Fatalf("DiscoverWithOptions() error = %v", err)
	}
	if info.BadgeURL != "https://tl.example.com/badge/opts" {
		t.Errorf("BadgeURL = %q", info.BadgeURL)
	}
}

func TestDNSDiscoverer_Discover_DiscoveryOnly(t *testing.T) {
	resolver := NewMockDNSResolver()
	resolver.WithDiscoveryRecords("discovery-only.example.com", []*ATIRecord{
		{
			FormatVersion: "ati1",
			AgentID:       "disc-agent",
			RAEndpoint:    "https://ra.example.com",
		},
	})

	d := NewDNSDiscoverer(resolver)
	info, err := d.Discover(context.Background(), "discovery-only.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if info.AgentID != "disc-agent" {
		t.Errorf("AgentID = %q, want disc-agent", info.AgentID)
	}
	if info.BadgeURL != "" {
		t.Errorf("BadgeURL = %q, want empty", info.BadgeURL)
	}
}
