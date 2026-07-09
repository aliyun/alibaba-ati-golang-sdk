package verify

import (
	"context"
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	openapiutil "github.com/alibabacloud-go/openapi-util/service"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

const (
	// defaultAliyunEndpoint and defaultTLBaseURL are fixed platform values and
	// are intentionally not customer-configurable.
	defaultAliyunEndpoint = "alidns.aliyuncs.com"
	defaultTLBaseURL      = "https://tl.atiagent.cn:8180"
	defaultAPIVersion     = "2015-01-09"
)

// AliyunATIConfig configures the Alibaba Cloud ATI marketplace discovery client.
// Only the access credentials are configurable; the API endpoint and TL base URL
// are fixed platform constants.
type AliyunATIConfig struct {
	AccessKeyID     string
	AccessKeySecret string
}

// MarketplaceEndpoint represents an endpoint returned from the marketplace API.
type MarketplaceEndpoint struct {
	Protocol    string
	AgentURL    string
	Transports  []string
	MetadataURL string
}

// MarketplaceAgentInfo represents the result from DescribeAtiAgentRegisterInfoMarket.
type MarketplaceAgentInfo struct {
	RequestID           string
	AgentRegisterInfoID string
	AgentID             string
	AgentDisplayName    string
	AgentHost           string
	AgentVersion        string
	AgentDescription    string
	Status              string
	TrustLevel          string
	Categories          []string
	TrustCardContent    string
	Endpoints           []MarketplaceEndpoint
}

// AliyunATIDiscovery queries the Alibaba Cloud ATI marketplace for agent discovery,
// while delegating badge lookups to the standard DNS resolver.
type AliyunATIDiscovery struct {
	config        AliyunATIConfig
	client        *openapi.Client
	dnsResolver   *StandardDNSResolver
	targetVersion string // optional: specific version to query (semver, e.g. "1.0.0")
}

// NewAliyunATIDiscovery creates a new marketplace discovery client using the official SDK.
func NewAliyunATIDiscovery(cfg AliyunATIConfig) (*AliyunATIDiscovery, error) {
	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" {
		return nil, fmt.Errorf("aliyun ati: AccessKeyID and AccessKeySecret are required")
	}

	config := &openapi.Config{
		AccessKeyId:     tea.String(cfg.AccessKeyID),
		AccessKeySecret: tea.String(cfg.AccessKeySecret),
	}
	config.Endpoint = tea.String(defaultAliyunEndpoint)

	client, err := openapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("aliyun ati: failed to create SDK client: %w", err)
	}

	return &AliyunATIDiscovery{
		config:      cfg,
		client:      client,
		dnsResolver: NewStandardDNSResolver(),
	}, nil
}

// SetTargetVersion sets the version to use in discovery queries.
// Accepts semver expressions: "1.0.0", "^1.0.0", "~1.0.0", ">=1.0.0".
// Pass empty string to query the latest version (default).
func (d *AliyunATIDiscovery) SetTargetVersion(version string) {
	d.targetVersion = version
}

// GetTargetVersion returns the current target version.
func (d *AliyunATIDiscovery) GetTargetVersion() string {
	return d.targetVersion
}

// DescribeAgent queries the marketplace by agentHost and optional version.
func (d *AliyunATIDiscovery) DescribeAgent(ctx context.Context, agentHost, agentVersion string) (*MarketplaceAgentInfo, error) {
	if agentHost == "" {
		return nil, fmt.Errorf("aliyun ati: agentHost is required")
	}

	params := &openapi.Params{
		Action:      tea.String("DescribeAtiAgentRegisterInfoMarket"),
		Version:     tea.String(defaultAPIVersion),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("POST"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("RPC"),
		Pathname:    tea.String("/"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
	}

	query := map[string]interface{}{
		"AgentHost": agentHost,
	}
	if agentVersion != "" {
		query["AgentVersion"] = agentVersion
	}

	request := &openapi.OpenApiRequest{
		Query: openapiutil.Query(query),
	}

	runtime := &util.RuntimeOptions{}

	result, err := d.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("aliyun ati: API call failed: %w", err)
	}

	return parseCallApiResponse(result)
}

// parseCallApiResponse parses the CallApi result into MarketplaceAgentInfo.
func parseCallApiResponse(result map[string]interface{}) (*MarketplaceAgentInfo, error) {
	if result == nil {
		return nil, nil
	}

	body, ok := result["body"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	agentID := strVal(body["AgentId"])
	if agentID == "" {
		return nil, nil
	}

	info := &MarketplaceAgentInfo{
		RequestID:           strVal(body["RequestId"]),
		AgentRegisterInfoID: strVal(body["AgentRegisterInfoId"]),
		AgentID:             agentID,
		AgentDisplayName:    strVal(body["AgentDisplayName"]),
		AgentHost:           strVal(body["AgentHost"]),
		AgentVersion:        strVal(body["AgentVersion"]),
		AgentDescription:    strVal(body["AgentDescription"]),
		Status:              strVal(body["Status"]),
		TrustLevel:          strVal(body["TrustLevel"]),
		Categories:          strSlice(body["Categories"]),
		TrustCardContent:    strVal(body["TrustCardContent"]),
	}

	if eps, ok := body["Endpoints"].([]interface{}); ok {
		for _, ep := range eps {
			if em, ok := ep.(map[string]interface{}); ok {
				info.Endpoints = append(info.Endpoints, MarketplaceEndpoint{
					Protocol:    strVal(em["Protocol"]),
					AgentURL:    strVal(em["AgentUrl"]),
					Transports:  strSlice(em["Transports"]),
					MetadataURL: strVal(em["MetadataUrl"]),
				})
			}
		}
	}

	return info, nil
}

// --- DNSResolver interface implementation ---

// LookupATIDiscovery queries the marketplace API instead of _ati DNS TXT records.
// If targetVersion is set via SetTargetVersion(), queries that specific version;
// otherwise queries the latest version.
func (d *AliyunATIDiscovery) LookupATIDiscovery(ctx context.Context, fqdn models.Fqdn) (ATIDiscoveryResult, error) {
	agent, err := d.DescribeAgent(ctx, fqdn.String(), d.targetVersion)
	if err != nil {
		return ATIDiscoveryResult{}, err
	}
	if agent == nil || !strings.EqualFold(agent.Status, "Active") {
		return ATIDiscoveryResult{Found: false}, nil
	}

	version, parseErr := models.ParseVersion(agent.AgentVersion)
	if parseErr != nil {
		return ATIDiscoveryResult{Found: false}, nil
	}

	protocol := ""
	if len(agent.Endpoints) > 0 {
		protocol = strings.ToLower(agent.Endpoints[0].Protocol)
	}

	var metadataURL string
	mode := ATIRecordModeDirect
	for _, ep := range agent.Endpoints {
		if ep.MetadataURL != "" {
			metadataURL = ep.MetadataURL
			mode = ATIRecordModeCard
			break
		}
	}

	record := &ATIRecord{
		ID:       agent.AgentID,
		RA:       "aliyun",
		Version:  version,
		Mode:     mode,
		Protocol: protocol,
		URL:      metadataURL,
	}

	return ATIDiscoveryResult{Found: true, Records: []*ATIRecord{record}}, nil
}

// LookupATIBadge delegates to DNS _ati-badge TXT record lookup.
func (d *AliyunATIDiscovery) LookupATIBadge(ctx context.Context, fqdn models.Fqdn) (DNSLookupResult, error) {
	return d.dnsResolver.LookupATIBadge(ctx, fqdn)
}

// FindBadgeForVersion delegates to DNS badge lookup.
func (d *AliyunATIDiscovery) FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*ATIBadgeRecord, error) {
	return d.dnsResolver.FindBadgeForVersion(ctx, fqdn, version)
}

// FindPreferredBadge delegates to DNS badge lookup.
func (d *AliyunATIDiscovery) FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*ATIBadgeRecord, error) {
	return d.dnsResolver.FindPreferredBadge(ctx, fqdn)
}

// --- Helper functions ---

func strVal(v interface{}) string {
	s, _ := v.(string)
	return s
}

func strSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
