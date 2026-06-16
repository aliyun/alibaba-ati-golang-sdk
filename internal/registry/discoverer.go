package registry

import (
	"context"
	"fmt"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

// RAAPIDiscoverer implements ati.AgentDiscoverer using the RA API.
type RAAPIDiscoverer struct {
	client *RAClient
}

// NewRAAPIDiscoverer creates a new RAAPIDiscoverer wrapping the given RAClient.
func NewRAAPIDiscoverer(client *RAClient) *RAAPIDiscoverer {
	return &RAAPIDiscoverer{client: client}
}

// Discover queries the RA API for agent information by FQDN.
func (d *RAAPIDiscoverer) Discover(ctx context.Context, fqdn string) (*ati.AgentInfo, error) {
	raInfo, err := d.client.GetAgentByFQDN(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("RA API discovery failed for %s: %w", fqdn, err)
	}

	return raAgentInfoToATI(fqdn, raInfo), nil
}

// DiscoverWithOptions queries the RA API with filtering options.
func (d *RAAPIDiscoverer) DiscoverWithOptions(ctx context.Context, fqdn string, opts ...ati.DiscoverOption) (*ati.AgentInfo, error) {
	return d.Discover(ctx, fqdn)
}

func raAgentInfoToATI(fqdn string, ra *RAAgentInfo) *ati.AgentInfo {
	return &ati.AgentInfo{
		FQDN:       fqdn,
		AgentID:    ra.AgentID,
		BadgeURL:   ra.BadgeURL,
		RAEndpoint: ra.RAEndpoint,
		Version:    ra.Version,
		Protocol:   ra.Protocol,
		Mode:       ra.Mode,
		Source:     ati.SourceRAAPI,
	}
}
