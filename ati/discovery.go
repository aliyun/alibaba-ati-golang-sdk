package ati

import "context"

// CompositeDiscoverer combines a primary and fallback discoverer.
// If the primary fails, the fallback is tried (if configured).
type CompositeDiscoverer struct {
	primary  AgentDiscoverer
	fallback AgentDiscoverer
}

// NewCompositeDiscoverer creates a new CompositeDiscoverer.
func NewCompositeDiscoverer(primary AgentDiscoverer, fallback AgentDiscoverer) *CompositeDiscoverer {
	return &CompositeDiscoverer{primary: primary, fallback: fallback}
}

// Discover discovers agent info using primary, falling back if needed.
func (c *CompositeDiscoverer) Discover(ctx context.Context, fqdn string) (*AgentInfo, error) {
	info, err := c.primary.Discover(ctx, fqdn)
	if err != nil && c.fallback != nil {
		return c.fallback.Discover(ctx, fqdn)
	}
	return info, err
}

// DiscoverWithOptions discovers agent info with options, falling back if needed.
func (c *CompositeDiscoverer) DiscoverWithOptions(ctx context.Context, fqdn string, opts ...DiscoverOption) (*AgentInfo, error) {
	info, err := c.primary.DiscoverWithOptions(ctx, fqdn, opts...)
	if err != nil && c.fallback != nil {
		return c.fallback.DiscoverWithOptions(ctx, fqdn, opts...)
	}
	return info, err
}
