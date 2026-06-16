package registry

import "time"

// AgentRegistrationResponse represents the response from agent registration via RA API.
type AgentRegistrationResponse struct {
	AgentID   string `json:"agentId"`
	ATIName   string `json:"ansName"`
	Status    string `json:"status"`
	BadgeURL  string `json:"badgeUrl,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// RAAgentInfo represents agent information returned from RA API.
type RAAgentInfo struct {
	AgentID      string    `json:"agentId"`
	ATIName      string    `json:"ansName"`
	AgentHost    string    `json:"agentHost"`
	Version      string    `json:"version"`
	Protocol     string    `json:"protocol,omitempty"`
	Mode         string    `json:"mode,omitempty"`
	Status       string    `json:"status"`
	RAEndpoint   string    `json:"raEndpoint,omitempty"`
	BadgeURL     string    `json:"badgeUrl,omitempty"`
	RegisteredAt time.Time `json:"registeredAt,omitempty"`
}

// BadgeResponse represents the badge information returned from RA API.
type BadgeResponse struct {
	BadgeURL    string `json:"badgeUrl"`
	BadgeStatus string `json:"badgeStatus"`
	AgentStatus string `json:"agentStatus"`
}

// AuditTrailResponse represents the audit trail for an agent.
type AuditTrailResponse struct {
	Records []AuditRecord `json:"records"`
	Total   int           `json:"total"`
}

// AuditRecord represents a single audit trail entry.
type AuditRecord struct {
	EventType string    `json:"eventType"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
}

// ListOption configures agent listing.
type ListOption func(*listConfig)

type listConfig struct {
	limit  int
	offset int
	host   string
}

// WithListLimit sets the maximum number of results.
func WithListLimit(limit int) ListOption {
	return func(c *listConfig) {
		c.limit = limit
	}
}

// WithListOffset sets the result offset.
func WithListOffset(offset int) ListOption {
	return func(c *listConfig) {
		c.offset = offset
	}
}

// WithListHost filters by agent host.
func WithListHost(host string) ListOption {
	return func(c *listConfig) {
		c.host = host
	}
}

// AuditOption configures audit trail queries.
type AuditOption func(*auditConfig)

type auditConfig struct {
	limit  int
	offset int
}

// WithAuditLimit sets the audit trail result limit.
func WithAuditLimit(limit int) AuditOption {
	return func(c *auditConfig) {
		c.limit = limit
	}
}

// WithAuditOffset sets the audit trail result offset.
func WithAuditOffset(offset int) AuditOption {
	return func(c *auditConfig) {
		c.offset = offset
	}
}
