package ati

import (
	"crypto/tls"
)

// NewServerTLSConfig creates a TLS configuration for an ATI agent server.
// Client certificate verification is ca_bundle driven: if a CA pool is
// configured via WithClientCA, client certificates are required and verified;
// otherwise client certificates are not requested.
func NewServerTLSConfig(opts ...ServerOption) (*tls.Config, error) {
	cfg := defaultServerConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.serverCert.Certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{cfg.serverCert}
	}

	if cfg.clientCAPool == nil {
		tlsConfig.ClientAuth = tls.NoClientCert
		return tlsConfig, nil
	}

	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = cfg.clientCAPool
	if cfg.verifyConn != nil {
		tlsConfig.VerifyConnection = cfg.verifyConn
	}

	return tlsConfig, nil
}
