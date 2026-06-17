package ati

import (
	"crypto/tls"
	"crypto/x509"
)

// ClientOption configures an AgentClient.
type ClientOption func(*clientConfig)

type clientConfig struct {
	identity   tls.Certificate
	caPool     *x509.CertPool
	policy     VerificationPolicy
	tlBaseURL  string
	discoverer AgentDiscoverer
	verifyConn func(tls.ConnectionState) error
}

func defaultClientConfig() *clientConfig {
	return &clientConfig{
		policy:    PolicyBadgeRequired,
		tlBaseURL: "https://tl.ansagent.cn",
	}
}

// WithMTLSCerts sets the client identity certificate for mTLS.
func WithMTLSCerts(cert tls.Certificate) ClientOption {
	return func(c *clientConfig) {
		c.identity = cert
	}
}

// WithClientCAs sets the root CA pool for server certificate verification.
func WithClientCAs(pool *x509.CertPool) ClientOption {
	return func(c *clientConfig) {
		c.caPool = pool
	}
}

// WithClientPolicy sets the client verification policy.
func WithClientPolicy(p VerificationPolicy) ClientOption {
	return func(c *clientConfig) {
		c.policy = p
	}
}

// WithClientTLBaseURL sets the TL base URL for badge verification.
func WithClientTLBaseURL(url string) ClientOption {
	return func(c *clientConfig) {
		c.tlBaseURL = url
	}
}

// WithDiscoverer sets the agent discoverer for the client.
func WithDiscoverer(d AgentDiscoverer) ClientOption {
	return func(c *clientConfig) {
		c.discoverer = d
	}
}

// WithVerifyConnection sets a custom TLS VerifyConnection callback.
func WithVerifyConnection(fn func(tls.ConnectionState) error) ClientOption {
	return func(c *clientConfig) {
		c.verifyConn = fn
	}
}

// ServerOption configures a server TLS configuration.
type ServerOption func(*serverConfig)

type serverConfig struct {
	serverCert        tls.Certificate
	clientPolicy      VerificationPolicy
	clientCAPool      *x509.CertPool
	verifyConn        func(tls.ConnectionState) error
	ignoreCheckClient bool
}

func defaultServerConfig() *serverConfig {
	return &serverConfig{
		clientPolicy: PolicyNone,
	}
}

// WithServerCert sets the server certificate.
func WithServerCert(cert tls.Certificate) ServerOption {
	return func(c *serverConfig) {
		c.serverCert = cert
	}
}

// WithClientCA sets the CA pool for client certificate verification.
func WithClientCA(pool *x509.CertPool) ServerOption {
	return func(c *serverConfig) {
		c.clientCAPool = pool
	}
}

// WithClientVerificationPolicy sets the server-side client verification policy.
func WithClientVerificationPolicy(p VerificationPolicy) ServerOption {
	return func(c *serverConfig) {
		c.clientPolicy = p
	}
}

// WithServerVerifyConnection sets a custom TLS VerifyConnection callback for the server.
func WithServerVerifyConnection(fn func(tls.ConnectionState) error) ServerOption {
	return func(c *serverConfig) {
		c.verifyConn = fn
	}
}

// WithIgnoreCheckClient skips server-side client certificate verification.
// When enabled, the server does not request or verify client certificates,
// and ca_bundle is not required regardless of the client verification policy.
func WithIgnoreCheckClient() ServerOption {
	return func(c *serverConfig) {
		c.ignoreCheckClient = true
	}
}
