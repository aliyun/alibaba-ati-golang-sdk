package ati

import "context"

// DiscoverySource indicates the source of agent discovery.
type DiscoverySource int

const (
	SourceDNS   DiscoverySource = iota
	SourceRAAPI
)

// AgentInfo holds information about a discovered agent.
type AgentInfo struct {
	FQDN       string
	AgentID    string
	BadgeURL   string
	RAEndpoint string
	Version    string
	Protocol   string
	Mode       string
	Source     DiscoverySource
}

// DiscoverOption configures discovery behavior.
type DiscoverOption func(*discoverConfig)

type discoverConfig struct {
	version  string
	protocol string
	source   *DiscoverySource
}

// WithVersion filters discovery results by version.
func WithVersion(version string) DiscoverOption {
	return func(c *discoverConfig) {
		c.version = version
	}
}

// WithProtocol filters discovery results by protocol.
func WithProtocol(protocol string) DiscoverOption {
	return func(c *discoverConfig) {
		c.protocol = protocol
	}
}

// WithSource restricts discovery to a specific source.
func WithSource(source DiscoverySource) DiscoverOption {
	return func(c *discoverConfig) {
		c.source = &source
	}
}

// AgentDiscoverer discovers agent information by FQDN.
type AgentDiscoverer interface {
	Discover(ctx context.Context, fqdn string) (*AgentInfo, error)
	DiscoverWithOptions(ctx context.Context, fqdn string, opts ...DiscoverOption) (*AgentInfo, error)
}
