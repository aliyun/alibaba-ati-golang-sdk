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
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
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

func TestNewServerTLSConfig_PolicyPKIOnly(t *testing.T) {
	cfg, err := NewServerTLSConfig(WithClientVerificationPolicy(PolicyPKIOnly))
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

func TestNewServerTLSConfig_PolicyBadgeRequired(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := NewServerTLSConfig(
		WithClientVerificationPolicy(PolicyBadgeRequired),
		WithClientCA(pool),
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

func TestNewServerTLSConfig_PolicyFull(t *testing.T) {
	called := false
	fn := func(tls.ConnectionState) error {
		called = true
		return nil
	}
	cfg, err := NewServerTLSConfig(
		WithClientVerificationPolicy(PolicyFull),
		WithServerVerifyConnection(fn),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection not set")
	}
	_ = called
}

func TestNewServerTLSConfig_PolicyNone_NoClientCAs(t *testing.T) {
	cfg, err := NewServerTLSConfig(WithClientVerificationPolicy(PolicyNone))
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil for PolicyNone")
	}
}
