package registry

import (
	"context"
	"fmt"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

// RAAPIDiscoverer implements ati.AgentDiscoverer using the Alibaba Cloud OpenAPI.
type RAAPIDiscoverer struct {
	client *RAClient
}

// NewRAAPIDiscoverer creates a new RAAPIDiscoverer wrapping the given RAClient.
func NewRAAPIDiscoverer(client *RAClient) *RAAPIDiscoverer {
	return &RAAPIDiscoverer{client: client}
}

// Discover queries DescribeAgentRegisterInfoMarket for agent information by host.
func (d *RAAPIDiscoverer) Discover(ctx context.Context, fqdn string) (*ati.AgentInfo, error) {
	result, err := d.client.DescribeAgentRegisterInfoMarket(ctx, fqdn, "")
	if err != nil {
		return nil, fmt.Errorf("RA API discovery failed for %s: %w", fqdn, err)
	}

	return marketResultToATI(fqdn, result), nil
}

// DiscoverWithOptions queries DescribeAgentRegisterInfoMarket with filtering options.
func (d *RAAPIDiscoverer) DiscoverWithOptions(ctx context.Context, fqdn string, opts ...ati.DiscoverOption) (*ati.AgentInfo, error) {
	version, _ := ati.ResolveDiscoverOptions(opts...)

	result, err := d.client.DescribeAgentRegisterInfoMarket(ctx, fqdn, version)
	if err != nil {
		return nil, fmt.Errorf("RA API discovery failed for %s: %w", fqdn, err)
	}

	return marketResultToATI(fqdn, result), nil
}

func marketResultToATI(fqdn string, r *DescribeAgentMarketPopResult) *ati.AgentInfo {
	info := &ati.AgentInfo{
		FQDN:       fqdn,
		AgentID:    r.AgentId,
		BadgeURL:   r.BadgeUrl,
		TrustLevel: r.TrustLevel,
		Categories: r.Categories,
		Version:    r.Version,
		Mode:       r.Mode,
		Source:     ati.SourceRAAPI,
	}

	for _, ep := range r.Endpoints {
		info.Endpoints = append(info.Endpoints, ati.AgentEndpoint{
			Host:     ep.Host,
			Port:     ep.Port,
			Protocol: ep.Protocol,
		})
		if info.Protocol == "" {
			info.Protocol = ep.Protocol
		}
	}

	return info
}
