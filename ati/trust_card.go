package ati

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

const defaultTLBaseURL = "https://tl.ansagent.cn:8180/ans/api/v1"

// GetTrustCard retrieves a Trust Card from the CNNIC Transparency Log.
// It resolves the agent's _ati TXT record to get the agentId, then queries the TL API.
func GetTrustCard(ctx context.Context, host string, version string, opts ...TrustCardOption) (*models.TrustCard, error) {
	cfg := &trustCardConfig{
		tlBaseURL:   defaultTLBaseURL,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
		dnsResolver: verify.NewStandardDNSResolver(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Step 1: Resolve _ati TXT to get agentId
	fqdn, err := models.NewFqdn(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}

	agentID, err := resolveAgentID(ctx, cfg.dnsResolver, fqdn)
	if err != nil {
		return nil, fmt.Errorf("failed to discover agent: %w", err)
	}

	// Step 2: Query CNNIC TL
	tlURL := fmt.Sprintf("%s/tl/agents/%s/logs/latest", cfg.tlBaseURL, agentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create TL request: %w", err)
	}

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TL query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TL query returned status %d", resp.StatusCode)
	}

	// Step 3: Parse TL response and extract Trust Card from payload
	var tlResp models.TLResponse
	if err := json.NewDecoder(resp.Body).Decode(&tlResp); err != nil {
		return nil, fmt.Errorf("failed to decode TL response: %w", err)
	}

	card := &models.TrustCard{
		AgentID:          tlResp.Payload.AgentID,
		AgentName:        tlResp.Payload.AgentName,
		AgentDisplayName: tlResp.Payload.AgentDisplayName,
		Version:          tlResp.Payload.Version,
		AgentHost:        tlResp.Payload.AgentHost,
	}

	return card, nil
}

// resolveAgentID looks up _ati TXT records and extracts the agent ID.
func resolveAgentID(ctx context.Context, resolver verify.DNSResolver, fqdn models.Fqdn) (string, error) {
	result, err := resolver.LookupATIDiscovery(ctx, fqdn)
	if err != nil {
		return "", err
	}
	if !result.Found || len(result.Records) == 0 {
		return "", fmt.Errorf("no _ati records found for %s", fqdn.String())
	}
	return result.Records[0].ID, nil
}

// TrustCardOption configures GetTrustCard behavior.
type TrustCardOption func(*trustCardConfig)

type trustCardConfig struct {
	tlBaseURL   string
	httpClient  *http.Client
	dnsResolver verify.DNSResolver
}

// withTLBaseURL overrides the default CNNIC TL base URL.
func withTLBaseURL(url string) TrustCardOption {
	return func(c *trustCardConfig) {
		c.tlBaseURL = url
	}
}
