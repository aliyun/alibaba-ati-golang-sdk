package models

// AgentCapabilityRequest represents a request to resolve an agent by host and version
type AgentCapabilityRequest struct {
	// AgentHost is the target agent host domain (required)
	AgentHost string `json:"agentHost"`
	// Version is the semver range to match: "*", "^1.0.0", "~1.2.3", "1.0.0" (required)
	Version string `json:"version"`
}

// AgentCapabilityResponse represents the response from agent resolution
type AgentCapabilityResponse struct {
	// ATIName is the resolved ATI name (e.g., ati://v1.0.0.myagent.example.com)
	ATIName string `json:"ansName"`
	// Links contains HATEOAS links for the resolved agent
	Links []Link `json:"links,omitempty"`
}
