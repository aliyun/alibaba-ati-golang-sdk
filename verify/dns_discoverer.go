package verify

import (
	"context"
	"fmt"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/models"
)

// DNSDiscoverer adapts the existing DNSResolver to the AgentDiscoverer interface.
type DNSDiscoverer struct {
	resolver DNSResolver
}

// NewDNSDiscoverer creates a new DNSDiscoverer wrapping the given resolver.
func NewDNSDiscoverer(resolver DNSResolver) *DNSDiscoverer {
	return &DNSDiscoverer{resolver: resolver}
}

// Discover queries DNS _ati and _ati-badge TXT records for the given FQDN.
func (d *DNSDiscoverer) Discover(ctx context.Context, fqdnStr string) (*ati.AgentInfo, error) {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return nil, fmt.Errorf("invalid FQDN: %w", err)
	}

	info := &ati.AgentInfo{
		FQDN:   fqdnStr,
		Source: ati.SourceDNS,
	}

	// Query _ati TXT for discovery metadata
	discoveryResult, err := d.resolver.LookupATIDiscovery(ctx, fqdn)
	if err == nil && discoveryResult.Found && len(discoveryResult.Records) > 0 {
		rec := discoveryResult.Records[0]
		info.AgentID = rec.AgentID
		info.RAEndpoint = rec.RAEndpoint
		info.Version = rec.Version
		info.Protocol = rec.Protocol
		info.Mode = rec.Mode
	}

	// Query _ati-badge TXT for badge URL
	badgeResult, err := d.resolver.LookupATIBadge(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("badge lookup failed: %w", err)
	}
	if badgeResult.Found && len(badgeResult.Records) > 0 {
		info.BadgeURL = badgeResult.Records[0].URL
		if info.Version == "" && badgeResult.Records[0].Version != nil {
			info.Version = badgeResult.Records[0].Version.String()
		}
	}

	if info.AgentID == "" && info.BadgeURL == "" {
		return nil, fmt.Errorf("no ATI records found for %s", fqdnStr)
	}

	return info, nil
}

// DiscoverWithOptions queries DNS with filtering options.
func (d *DNSDiscoverer) DiscoverWithOptions(ctx context.Context, fqdn string, opts ...ati.DiscoverOption) (*ati.AgentInfo, error) {
	return d.Discover(ctx, fqdn)
}
