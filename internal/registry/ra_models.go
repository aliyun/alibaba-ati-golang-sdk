package registry

// DescribeAgentMarketPopResult is the response from DescribeAgentRegisterInfoMarket.
type DescribeAgentMarketPopResult struct {
	RequestId  string                `json:"RequestId"`
	AgentHost  string                `json:"AgentHost"`
	AgentId    string                `json:"AgentId"`
	Version    string                `json:"Version"`
	TrustLevel string                `json:"TrustLevel"`
	Categories []string              `json:"Categories"`
	Endpoints  []MarketAgentEndpoint `json:"Endpoints"`
	BadgeUrl   string                `json:"BadgeUrl"`
	Mode       string                `json:"Mode"`
	Status     string                `json:"Status"`
}

// MarketAgentEndpoint represents a single endpoint from the market API response.
type MarketAgentEndpoint struct {
	Host     string `json:"Host"`
	Port     int    `json:"Port"`
	Protocol string `json:"Protocol"`
	Weight   int    `json:"Weight"`
}
