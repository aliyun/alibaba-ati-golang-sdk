package ati

import (
	"context"
	"errors"
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/internal/registry"
	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// DiscoveryOption configures a DiscoverAgents call.
type DiscoveryOption func(*discoveryConfig)

type discoveryConfig struct {
	name        string
	host        string
	version     string
	limit       int
	offset      int
	registryURL string
	apiKey      string
	apiSecret   string
}

// WithSearchName filters agents by display name.
func WithSearchName(name string) DiscoveryOption {
	return func(c *discoveryConfig) { c.name = name }
}

// WithSearchHost filters agents by host domain.
func WithSearchHost(host string) DiscoveryOption {
	return func(c *discoveryConfig) { c.host = host }
}

// WithSearchVersion filters agents by version.
func WithSearchVersion(version string) DiscoveryOption {
	return func(c *discoveryConfig) { c.version = version }
}

// WithSearchLimit sets the maximum number of results (1-1000).
func WithSearchLimit(n int) DiscoveryOption {
	return func(c *discoveryConfig) { c.limit = n }
}

// WithSearchOffset sets the pagination offset.
func WithSearchOffset(n int) DiscoveryOption {
	return func(c *discoveryConfig) { c.offset = n }
}

// WithRegistryURL overrides the default RA API base URL.
func WithRegistryURL(url string) DiscoveryOption {
	return func(c *discoveryConfig) { c.registryURL = url }
}

// WithRegistryAuth sets API key authentication for the registry.
func WithRegistryAuth(key, secret string) DiscoveryOption {
	return func(c *discoveryConfig) {
		c.apiKey = key
		c.apiSecret = secret
	}
}

// DiscoverAgents searches the ATI marketplace registry for agents.
//
// At least one search criterion (name, host, or version) must be provided.
//
// Note: the current registry API returns basic agent info (name, host, version,
// endpoints). Detailed agent info (full trust card, etc.) will be available in
// a future API version.
func DiscoverAgents(ctx context.Context, opts ...DiscoveryOption) (*models.AgentSearchResponse, error) {
	cfg := &discoveryConfig{
		limit: 20,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.name == "" && cfg.host == "" && cfg.version == "" {
		return nil, errors.New("at least one search criterion is required: use WithSearchName, WithSearchHost, or WithSearchVersion")
	}

	var regOpts []registry.Option
	if cfg.registryURL != "" {
		regOpts = append(regOpts, registry.WithBaseURL(cfg.registryURL))
	}
	if cfg.apiKey != "" {
		regOpts = append(regOpts, registry.WithAPIKey(cfg.apiKey, cfg.apiSecret))
	}

	client, err := registry.NewClient(regOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	result, err := client.SearchAgents(ctx, cfg.name, cfg.host, cfg.version, cfg.limit, cfg.offset)
	if err != nil {
		return nil, fmt.Errorf("agent search failed: %w", err)
	}

	return result, nil
}
