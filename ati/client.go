package ati

import (
	"crypto/tls"
	"io"
	"net/http"
)

// AgentClient is an mTLS HTTP client with ATI verification.
// Default policy is PolicyPKIBadge with TLS 1.3.
type AgentClient struct {
	httpClient *http.Client
	policy     VerificationPolicy
	discoverer AgentDiscoverer
	tlBaseURL  string
}

// NewAgentClient creates a new mTLS-capable HTTP client.
func NewAgentClient(opts ...ClientOption) (*AgentClient, error) {
	cfg := defaultClientConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.identity.Certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{cfg.identity}
	}
	if cfg.caPool != nil {
		tlsConfig.RootCAs = cfg.caPool
	}
	if cfg.verifyConn != nil {
		tlsConfig.VerifyConnection = cfg.verifyConn
	}

	return &AgentClient{
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		policy:     cfg.policy,
		discoverer: cfg.discoverer,
		tlBaseURL:  cfg.tlBaseURL,
	}, nil
}

// HTTPClient returns the underlying http.Client for direct use.
func (c *AgentClient) HTTPClient() *http.Client {
	return c.httpClient
}

// Policy returns the configured verification policy.
func (c *AgentClient) Policy() VerificationPolicy {
	return c.policy
}

// Do executes an HTTP request using the mTLS-configured client.
func (c *AgentClient) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

// Get performs an HTTP GET request.
func (c *AgentClient) Get(url string) (*http.Response, error) {
	return c.httpClient.Get(url)
}

// Post performs an HTTP POST request.
func (c *AgentClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.httpClient.Post(url, contentType, body)
}
