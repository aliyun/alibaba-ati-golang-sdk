package ati

import (
	"crypto/tls"
	"fmt"
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
	case PolicyPKIOnly:
		if cfg.clientCAPool == nil {
			return nil, fmt.Errorf("PolicyPKIOnly requires ca_bundle (clientCAPool)")
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = cfg.clientCAPool
		if cfg.verifyConn != nil {
			tlsConfig.VerifyConnection = cfg.verifyConn
		}
	case PolicyBadgeRequired, PolicyFull:
		if cfg.clientCAPool != nil {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = cfg.clientCAPool
		} else {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
		}
		if cfg.verifyConn != nil {
			tlsConfig.VerifyConnection = cfg.verifyConn
		}
	}

	return tlsConfig, nil
}
