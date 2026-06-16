package ati

import (
	"context"
	"errors"
	"testing"
)

type mockDiscoverer struct {
	info *AgentInfo
	err  error
}

func (m *mockDiscoverer) Discover(_ context.Context, _ string) (*AgentInfo, error) {
	return m.info, m.err
}

func (m *mockDiscoverer) DiscoverWithOptions(_ context.Context, _ string, _ ...DiscoverOption) (*AgentInfo, error) {
	return m.info, m.err
}

func TestCompositeDiscoverer_PrimarySuccess(t *testing.T) {
	primary := &mockDiscoverer{info: &AgentInfo{FQDN: "a.example.com", AgentID: "agent-1"}}
	fallback := &mockDiscoverer{info: &AgentInfo{FQDN: "a.example.com", AgentID: "agent-fallback"}}
	cd := NewCompositeDiscoverer(primary, fallback)

	info, err := cd.Discover(context.Background(), "a.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if info.AgentID != "agent-1" {
		t.Errorf("AgentID = %s, want agent-1", info.AgentID)
	}
}

func TestCompositeDiscoverer_PrimaryFails_FallbackSuccess(t *testing.T) {
	primary := &mockDiscoverer{err: errors.New("primary failed")}
	fallback := &mockDiscoverer{info: &AgentInfo{FQDN: "a.example.com", AgentID: "agent-fallback"}}
	cd := NewCompositeDiscoverer(primary, fallback)

	info, err := cd.Discover(context.Background(), "a.example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if info.AgentID != "agent-fallback" {
		t.Errorf("AgentID = %s, want agent-fallback", info.AgentID)
	}
}

func TestCompositeDiscoverer_PrimaryFails_NoFallback(t *testing.T) {
	primary := &mockDiscoverer{err: errors.New("primary failed")}
	cd := NewCompositeDiscoverer(primary, nil)

	_, err := cd.Discover(context.Background(), "a.example.com")
	if err == nil {
		t.Fatal("expected error when primary fails and no fallback")
	}
}

func TestCompositeDiscoverer_DiscoverWithOptions_PrimarySuccess(t *testing.T) {
	primary := &mockDiscoverer{info: &AgentInfo{FQDN: "a.example.com", AgentID: "agent-1"}}
	fallback := &mockDiscoverer{info: &AgentInfo{FQDN: "a.example.com", AgentID: "agent-fallback"}}
	cd := NewCompositeDiscoverer(primary, fallback)

	info, err := cd.DiscoverWithOptions(context.Background(), "a.example.com", WithVersion("1.0"))
	if err != nil {
		t.Fatalf("DiscoverWithOptions() error = %v", err)
	}
	if info.AgentID != "agent-1" {
		t.Errorf("AgentID = %s, want agent-1", info.AgentID)
	}
}

func TestCompositeDiscoverer_DiscoverWithOptions_Fallback(t *testing.T) {
	primary := &mockDiscoverer{err: errors.New("fail")}
	fallback := &mockDiscoverer{info: &AgentInfo{FQDN: "b.example.com", AgentID: "fb"}}
	cd := NewCompositeDiscoverer(primary, fallback)

	info, err := cd.DiscoverWithOptions(context.Background(), "b.example.com")
	if err != nil {
		t.Fatalf("DiscoverWithOptions() error = %v", err)
	}
	if info.AgentID != "fb" {
		t.Errorf("AgentID = %s, want fb", info.AgentID)
	}
}

func TestCompositeDiscoverer_DiscoverWithOptions_NoFallback(t *testing.T) {
	primary := &mockDiscoverer{err: errors.New("fail")}
	cd := NewCompositeDiscoverer(primary, nil)

	_, err := cd.DiscoverWithOptions(context.Background(), "b.example.com")
	if err == nil {
		t.Fatal("expected error when primary fails and no fallback")
	}
}

func TestNewCompositeDiscoverer(t *testing.T) {
	p := &mockDiscoverer{}
	f := &mockDiscoverer{}
	cd := NewCompositeDiscoverer(p, f)
	if cd.primary != p {
		t.Error("primary not set")
	}
	if cd.fallback != f {
		t.Error("fallback not set")
	}
}
