package registry

import (
	"context"
	"fmt"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	openapiutil "github.com/alibabacloud-go/openapi-util/service"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/aliyun/credentials-go/credentials"
)

// RAClient wraps the Alibaba Cloud OpenAPI SDK for agent discovery via POP RPC.
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
		Type:            dara.String("access_key"),
		AccessKeyId:     dara.String(cfg.accessKeyID),
		AccessKeySecret: dara.String(cfg.accessKeySecret),
	}
	cred, err := credentials.NewCredential(credConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	apiConfig := &openapi.Config{
		Credential: cred,
		Endpoint:   dara.String(cfg.endpoint),
	}
	client, err := openapi.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAPI client: %w", err)
	}

	return &RAClient{client: client, endpoint: cfg.endpoint}, nil
}

// DescribeAgentRegisterInfoMarket queries agent registration info via POP RPC.
func (c *RAClient) DescribeAgentRegisterInfoMarket(ctx context.Context, agentHost string, agentVersion string) (*DescribeAgentMarketPopResult, error) {
	params := &openapi.Params{
		Action:      dara.String("DescribeAgentRegisterInfoMarket"),
		Version:     dara.String("2015-01-09"),
		Protocol:    dara.String("HTTPS"),
		Pathname:    dara.String("/"),
		Method:      dara.String("POST"),
		AuthType:    dara.String("AK"),
		Style:       dara.String("RPC"),
		ReqBodyType: dara.String("formData"),
		BodyType:    dara.String("json"),
	}

	queries := map[string]interface{}{
		"AgentHost": agentHost,
	}
	if agentVersion != "" {
		queries["AgentVersion"] = agentVersion
	}

	request := &openapi.OpenApiRequest{
		Query: openapiutil.Query(queries),
	}

	runtime := &dara.RuntimeOptions{
		ConnectTimeout: dara.Int(defaultConnectTimeoutMs),
		ReadTimeout:    dara.Int(defaultReadTimeoutMs),
	}

	resp, err := c.callApiWithContext(ctx, params, request, runtime)
	if err != nil {
		return nil, fmt.Errorf("DescribeAgentRegisterInfoMarket API call failed: %w", err)
	}

	var result DescribeAgentMarketPopResult
	if err := dara.Convert(resp["body"], &result); err != nil {
		return nil, fmt.Errorf("failed to parse DescribeAgentRegisterInfoMarket response: %w", err)
	}

	return &result, nil
}

// callApiWithContext wraps CallApi to respect context cancellation/timeout.
func (c *RAClient) callApiWithContext(ctx context.Context, params *openapi.Params, request *openapi.OpenApiRequest, runtime *dara.RuntimeOptions) (map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		ms := int(remaining.Milliseconds())
		if runtime.ConnectTimeout == nil || ms < dara.IntValue(runtime.ConnectTimeout) {
			runtime.ConnectTimeout = dara.Int(ms)
		}
		if runtime.ReadTimeout == nil || ms < dara.IntValue(runtime.ReadTimeout) {
			runtime.ReadTimeout = dara.Int(ms)
		}
	}

	resp, err := c.client.CallApi(params, request, runtime)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return resp, nil
}

const (
	defaultConnectTimeoutMs = 10000
	defaultReadTimeoutMs    = 30000
)
