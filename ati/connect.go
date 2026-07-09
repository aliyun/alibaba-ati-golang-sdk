package ati

import (
	"context"
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// ConnectRequest is the entry point for establishing an ATI connection.
type ConnectRequest struct {
	Target  string `json:"target"`
	Version string `json:"version,omitempty"`
}

// ConnectResult represents the outcome of a connection attempt.
type ConnectResult struct {
	AgentID  string
	Endpoint string
}

// Connect validates a target host via _ati DNS lookup and returns the connection endpoint.
// The caller provides host and version directly; no marketplace/service discovery is performed.
func (c *AgentClient) Connect(ctx context.Context, req ConnectRequest) (*ConnectResult, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("connect: target is required")
	}

	fqdn, err := models.NewFqdn(req.Target)
	if err != nil {
		return nil, fmt.Errorf("connect: invalid target %q: %w", req.Target, err)
	}

	// Validate host via _ati DNS lookup
	discovery, err := c.dnsResolver.LookupATIDiscovery(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("connect: DNS validation failed: %w", err)
	}
	if !discovery.Found || len(discovery.Records) == 0 {
		return nil, fmt.Errorf("connect: no _ati record found for %s", req.Target)
	}

	agentID := discovery.Records[0].ID
	endpoint := fmt.Sprintf("https://%s", req.Target)

	return &ConnectResult{
		AgentID:  agentID,
		Endpoint: endpoint,
	}, nil
}
