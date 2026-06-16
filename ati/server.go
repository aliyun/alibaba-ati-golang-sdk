package ati

import (
	"crypto/tls"
)

// NewServerTLSConfig creates a TLS configuration for an ATI agent server.
// Default client verification policy is PolicyNone (no client cert required).
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

	switch cfg.clientPolicy {
	case PolicyNone:
		tlsConfig.ClientAuth = tls.NoClientCert
	case PolicyPKIOnly, PolicyBadgeRequired, PolicyFull:
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if cfg.clientCAPool != nil {
			tlsConfig.ClientCAs = cfg.clientCAPool
		}
		if cfg.verifyConn != nil {
			tlsConfig.VerifyConnection = cfg.verifyConn
		}
	}

	return tlsConfig, nil
}
