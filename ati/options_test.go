package ati

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestDefaultClientConfig(t *testing.T) {
	cfg := defaultClientConfig()
	if cfg.policy != PolicyPKIBadge {
		t.Errorf("default policy = %v, want PolicyPKIBadge", cfg.policy)
	}
	if cfg.tlBaseURL != "https://tl.ansagent.cn" {
		t.Errorf("default tlBaseURL = %v, want https://tl.ansagent.cn", cfg.tlBaseURL)
	}
}

func TestWithMTLSCerts(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	cfg := defaultClientConfig()
	WithMTLSCerts(cert)(cfg)
	if len(cfg.identity.Certificate) != 1 {
		t.Errorf("identity certificate not set")
	}
}

func TestWithClientCAs(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := defaultClientConfig()
	WithClientCAs(pool)(cfg)
	if cfg.caPool != pool {
		t.Error("caPool not set")
	}
}

func TestWithClientPolicy(t *testing.T) {
	cfg := defaultClientConfig()
	WithClientPolicy(PolicyPKIBadgeDANE)(cfg)
	if cfg.policy != PolicyPKIBadgeDANE {
		t.Errorf("policy = %v, want PolicyPKIBadgeDANE", cfg.policy)
	}
}

func TestWithClientTLBaseURL(t *testing.T) {
	cfg := defaultClientConfig()
	WithClientTLBaseURL("https://custom.example.com")(cfg)
	if cfg.tlBaseURL != "https://custom.example.com" {
		t.Errorf("tlBaseURL = %v, want https://custom.example.com", cfg.tlBaseURL)
	}
}

func TestWithDiscoverer_Option(t *testing.T) {
	d := &mockDiscoverer{}
	cfg := defaultClientConfig()
	WithDiscoverer(d)(cfg)
	if cfg.discoverer != d {
		t.Error("discoverer not set")
	}
}

func TestWithVerifyConnection_Option(t *testing.T) {
	fn := func(tls.ConnectionState) error { return nil }
	cfg := defaultClientConfig()
	WithVerifyConnection(fn)(cfg)
	if cfg.verifyConn == nil {
		t.Error("verifyConn not set")
	}
}

func TestDefaultServerConfig(t *testing.T) {
	cfg := defaultServerConfig()
	if cfg.clientPolicy != PolicyPKIBadge {
		t.Errorf("default clientPolicy = %v, want PolicyPKIBadge", cfg.clientPolicy)
	}
}

func TestWithServerCert(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{4, 5, 6}}}
	cfg := defaultServerConfig()
	WithServerCert(cert)(cfg)
	if len(cfg.serverCert.Certificate) != 1 {
		t.Errorf("serverCert not set")
	}
}

func TestWithClientCA(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := defaultServerConfig()
	WithClientCA(pool)(cfg)
	if cfg.clientCAPool != pool {
		t.Error("clientCAPool not set")
	}
}

func TestWithClientVerificationPolicy(t *testing.T) {
	cfg := defaultServerConfig()
	WithClientVerificationPolicy(PolicyPKI)(cfg)
	if cfg.clientPolicy != PolicyPKI {
		t.Errorf("clientPolicy = %v, want PolicyPKI", cfg.clientPolicy)
	}
}

func TestWithServerVerifyConnection(t *testing.T) {
	fn := func(tls.ConnectionState) error { return nil }
	cfg := defaultServerConfig()
	WithServerVerifyConnection(fn)(cfg)
	if cfg.verifyConn == nil {
		t.Error("verifyConn not set")
	}
}
