package ati

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestNewServerTLSConfig_Defaults(t *testing.T) {
	cfg, err := NewServerTLSConfig()
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert (no ca_bundle)", cfg.ClientAuth)
	}
}

func TestNewServerTLSConfig_WithServerCert(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	cfg, err := NewServerTLSConfig(WithServerCert(cert))
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates length = %d, want 1", len(cfg.Certificates))
	}
}

func TestNewServerTLSConfig_NoCABundle_NoClientCert(t *testing.T) {
	cfg, err := NewServerTLSConfig()
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no ca_bundle configured")
	}
}

func TestNewServerTLSConfig_WithCABundle_RequireAndVerify(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := NewServerTLSConfig(WithClientCA(pool))
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != pool {
		t.Error("ClientCAs not set to provided pool")
	}
}

func TestNewServerTLSConfig_WithCABundle_PolicyPKI(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := NewServerTLSConfig(
		WithClientCA(pool),
		WithClientVerificationPolicy(PolicyPKI),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != pool {
		t.Error("ClientCAs not set")
	}
}

func TestNewServerTLSConfig_WithCABundle_PolicyPKIBadge(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := NewServerTLSConfig(
		WithClientCA(pool),
		WithClientVerificationPolicy(PolicyPKIBadge),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != pool {
		t.Error("ClientCAs not set")
	}
}

func TestNewServerTLSConfig_WithCABundle_PolicyPKIBadgeDANE(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := NewServerTLSConfig(
		WithClientCA(pool),
		WithClientVerificationPolicy(PolicyPKIBadgeDANE),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != pool {
		t.Error("ClientCAs not set")
	}
}

func TestNewServerTLSConfig_WithCABundle_VerifyConnection(t *testing.T) {
	pool := x509.NewCertPool()
	called := false
	fn := func(tls.ConnectionState) error {
		called = true
		return nil
	}
	cfg, err := NewServerTLSConfig(
		WithClientCA(pool),
		WithServerVerifyConnection(fn),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection not set")
	}
	_ = called
}

func TestNewServerTLSConfig_NoCABundle_VerifyConnectionIgnored(t *testing.T) {
	fn := func(tls.ConnectionState) error { return nil }
	cfg, err := NewServerTLSConfig(
		WithServerVerifyConnection(fn),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert (no ca_bundle)", cfg.ClientAuth)
	}
}
