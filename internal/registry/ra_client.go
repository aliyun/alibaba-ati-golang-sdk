package registry

import (
	"context"
	"fmt"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	openapiutil "github.com/alibabacloud-go/openapi-util/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
)

// RAClient wraps the Alibaba Cloud OpenAPI SDK for RA API calls.
type RAClient struct {
	client   *openapi.Client
	endpoint string
}

// NewRAClient creates a new RAClient using AK/SK authentication.
func NewRAClient(opts ...RAClientOption) (*RAClient, error) {
	cfg := defaultRAConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.accessKeyID == "" || cfg.accessKeySecret == "" {
		return nil, fmt.Errorf("access key ID and secret are required")
	}

	credConfig := &credentials.Config{
		Type:            tea.String("access_key"),
		AccessKeyId:     tea.String(cfg.accessKeyID),
		AccessKeySecret: tea.String(cfg.accessKeySecret),
	}
	cred, err := credentials.NewCredential(credConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	apiConfig := &openapi.Config{
		Credential: cred,
		Endpoint:   tea.String(cfg.endpoint),
	}
	client, err := openapi.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAPI client: %w", err)
	}

	return &RAClient{client: client, endpoint: cfg.endpoint}, nil
}

// GetAgent retrieves agent information by agent ID.
func (c *RAClient) GetAgent(ctx context.Context, agentID string) (*RAAgentInfo, error) {
	params := &openapi.Params{
		Action:      tea.String("GetAgent"),
		Version:     tea.String("2024-01-01"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("GET"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
		Pathname:    tea.String("/agents/" + agentID),
	}

	request := &openapi.OpenApiRequest{
		Headers: map[string]*string{
			"Accept": tea.String("application/json"),
		},
	}

	runtime := &tea.RuntimeObject{
		ConnectTimeout: tea.Int(defaultConnectTimeoutMs),
		ReadTimeout:    tea.Int(defaultReadTimeoutMs),
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("GetAgent API call failed: %w", err)
	}

	var info RAAgentInfo
	if err := tea.Convert(resp["body"], &info); err != nil {
		return nil, fmt.Errorf("failed to parse GetAgent response: %w", err)
	}

	return &info, nil
}

// GetAgentByFQDN retrieves agent information by FQDN.
func (c *RAClient) GetAgentByFQDN(ctx context.Context, fqdn string) (*RAAgentInfo, error) {
	params := &openapi.Params{
		Action:      tea.String("GetAgentByFQDN"),
		Version:     tea.String("2024-01-01"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("GET"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
		Pathname:    tea.String("/agents/lookup"),
	}

	request := &openapi.OpenApiRequest{
		Headers: map[string]*string{
			"Accept": tea.String("application/json"),
		},
		Query: openapiutil.Query(map[string]interface{}{
			"host": fqdn,
		}),
	}

	runtime := &tea.RuntimeObject{
		ConnectTimeout: tea.Int(defaultConnectTimeoutMs),
		ReadTimeout:    tea.Int(defaultReadTimeoutMs),
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("GetAgentByFQDN API call failed: %w", err)
	}

	var info RAAgentInfo
	if err := tea.Convert(resp["body"], &info); err != nil {
		return nil, fmt.Errorf("failed to parse GetAgentByFQDN response: %w", err)
	}

	return &info, nil
}

// GetAgentBadge retrieves badge information for an agent.
func (c *RAClient) GetAgentBadge(ctx context.Context, agentID string) (*BadgeResponse, error) {
	params := &openapi.Params{
		Action:      tea.String("GetAgentBadge"),
		Version:     tea.String("2024-01-01"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("GET"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
		Pathname:    tea.String("/agents/" + agentID + "/badge"),
	}

	request := &openapi.OpenApiRequest{
		Headers: map[string]*string{
			"Accept": tea.String("application/json"),
		},
	}

	runtime := &tea.RuntimeObject{
		ConnectTimeout: tea.Int(defaultConnectTimeoutMs),
		ReadTimeout:    tea.Int(defaultReadTimeoutMs),
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("GetAgentBadge API call failed: %w", err)
	}

	var badge BadgeResponse
	if err := tea.Convert(resp["body"], &badge); err != nil {
		return nil, fmt.Errorf("failed to parse GetAgentBadge response: %w", err)
	}

	return &badge, nil
}

// RegisterAgent registers a new agent via the RA API.
func (c *RAClient) RegisterAgent(ctx context.Context, req *AgentRegistrationRequest) (*AgentRegistrationResponse, error) {
	params := &openapi.Params{
		Action:      tea.String("RegisterAgent"),
		Version:     tea.String("2024-01-01"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("POST"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
		Pathname:    tea.String("/agents"),
	}

	body, err := tea.ToMap(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize registration request: %w", err)
	}

	request := &openapi.OpenApiRequest{
		Headers: map[string]*string{
			"Content-Type": tea.String("application/json"),
			"Accept":       tea.String("application/json"),
		},
		Body: body,
	}

	runtime := &tea.RuntimeObject{
		ConnectTimeout: tea.Int(defaultConnectTimeoutMs),
		ReadTimeout:    tea.Int(defaultReadTimeoutMs),
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("RegisterAgent API call failed: %w", err)
	}

	var result AgentRegistrationResponse
	if err := tea.Convert(resp["body"], &result); err != nil {
		return nil, fmt.Errorf("failed to parse RegisterAgent response: %w", err)
	}

	return &result, nil
}

// AgentRegistrationRequest represents a registration request for the RA API.
type AgentRegistrationRequest struct {
	AgentHost    string `json:"agentHost"`
	AgentName    string `json:"agentDisplayName"`
	Version      string `json:"version"`
	IdentityCSR  string `json:"identityCsrPEM"`
	ServerCSR    string `json:"serverCsrPEM,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
}

// ListAgents lists agents via the RA API.
func (c *RAClient) ListAgents(ctx context.Context, opts ...ListOption) ([]*RAAgentInfo, error) {
	cfg := &listConfig{limit: 20, offset: 0}
	for _, opt := range opts {
		opt(cfg)
	}

	query := map[string]interface{}{
		"limit":  cfg.limit,
		"offset": cfg.offset,
	}
	if cfg.host != "" {
		query["host"] = cfg.host
	}

	params := &openapi.Params{
		Action:      tea.String("ListAgents"),
		Version:     tea.String("2024-01-01"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("GET"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
		Pathname:    tea.String("/agents"),
	}

	request := &openapi.OpenApiRequest{
		Headers: map[string]*string{
			"Accept": tea.String("application/json"),
		},
		Query: openapiutil.Query(query),
	}

	runtime := &tea.RuntimeObject{
		ConnectTimeout: tea.Int(defaultConnectTimeoutMs),
		ReadTimeout:    tea.Int(defaultReadTimeoutMs),
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("ListAgents API call failed: %w", err)
	}

	var agents []*RAAgentInfo
	if err := tea.Convert(resp["body"], &agents); err != nil {
		return nil, fmt.Errorf("failed to parse ListAgents response: %w", err)
	}

	return agents, nil
}

// GetAuditTrail retrieves the audit trail for an agent.
func (c *RAClient) GetAuditTrail(ctx context.Context, agentID string, opts ...AuditOption) (*AuditTrailResponse, error) {
	cfg := &auditConfig{limit: 20, offset: 0}
	for _, opt := range opts {
		opt(cfg)
	}

	params := &openapi.Params{
		Action:      tea.String("GetAuditTrail"),
		Version:     tea.String("2024-01-01"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("GET"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("ROA"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
		Pathname:    tea.String("/agents/" + agentID + "/audit"),
	}

	request := &openapi.OpenApiRequest{
		Headers: map[string]*string{
			"Accept": tea.String("application/json"),
		},
		Query: openapiutil.Query(map[string]interface{}{
			"limit":  cfg.limit,
			"offset": cfg.offset,
		}),
	}

	runtime := &tea.RuntimeObject{
		ConnectTimeout: tea.Int(defaultConnectTimeoutMs),
		ReadTimeout:    tea.Int(defaultReadTimeoutMs),
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("GetAuditTrail API call failed: %w", err)
	}

	var trail AuditTrailResponse
	if err := tea.Convert(resp["body"], &trail); err != nil {
		return nil, fmt.Errorf("failed to parse GetAuditTrail response: %w", err)
	}

	return &trail, nil
}

const (
	defaultConnectTimeoutMs = 10000
	defaultReadTimeoutMs    = 30000
)

