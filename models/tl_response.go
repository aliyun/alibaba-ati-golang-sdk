package models

// TLAgentStatus represents the agent status in a TL response.
type TLAgentStatus string

const (
	TLStatusActive     TLAgentStatus = "ACTIVE"
	TLStatusWarning    TLAgentStatus = "WARNING"
	TLStatusDeprecated TLAgentStatus = "DEPRECATED"
	TLStatusExpired    TLAgentStatus = "EXPIRED"
	TLStatusRevoked    TLAgentStatus = "REVOKED"
)

// IsValidForConnection returns true if the status allows connections.
func (s TLAgentStatus) IsValidForConnection() bool {
	switch s {
	case TLStatusActive, TLStatusWarning, TLStatusDeprecated:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the status is a terminal state.
func (s TLAgentStatus) IsTerminal() bool {
	return s == TLStatusRevoked || s == TLStatusExpired
}

// TLCertificates holds certificate fingerprints in a TL response.
type TLCertificates struct {
	ServerCertFingerprint   string `json:"serverCertFingerprint"`
	IdentityCertFingerprint string `json:"identityCertFingerprint"`
}

// TLPayload represents the payload section of a TL response.
type TLPayload struct {
	LogID            string         `json:"logId"`
	AgentID          string         `json:"agentId"`
	AgentName        string         `json:"agentName"`
	AgentDisplayName string         `json:"agentDisplayName"`
	AgentHost        string         `json:"agentHost"`
	AgentStatus      string         `json:"agentStatus"`
	Version          string         `json:"version"`
	Certificates     TLCertificates `json:"certificates"`
}

// ServerCertFingerprint returns the server certificate fingerprint.
func (p TLPayload) ServerCertFingerprint() string {
	return p.Certificates.ServerCertFingerprint
}

// IdentityCertFingerprint returns the identity certificate fingerprint.
func (p TLPayload) IdentityCertFingerprint() string {
	return p.Certificates.IdentityCertFingerprint
}

// TLResponse represents a response from the Transparency Log service.
type TLResponse struct {
	Status        string    `json:"status"`
	SchemaVersion string    `json:"schemaVersion,omitempty"`
	Payload       TLPayload `json:"payload"`
}
