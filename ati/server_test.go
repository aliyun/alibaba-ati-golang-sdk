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

func TestNewServerTLSConfig_PolicyPKIOnly_WithCABundle(t *testing.T) {
	pool := x509.NewCertPool()
	cfg, err := NewServerTLSConfig(
		WithClientVerificationPolicy(PolicyPKIOnly),
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

func TestNewServerTLSConfig_PolicyPKIOnly_NoCABundle_Error(t *testing.T) {
	_, err := NewServerTLSConfig(WithClientVerificationPolicy(PolicyPKIOnly))
	if err == nil {
		t.Fatal("expected error for PolicyPKIOnly without ca_bundle, got nil")
	}
}

func TestNewServerTLSConfig_PolicyBadgeRequired_WithCABundle(t *testing.T) {
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

func TestNewServerTLSConfig_PolicyBadgeRequired_NoCABundle(t *testing.T) {
	cfg, err := NewServerTLSConfig(WithClientVerificationPolicy(PolicyBadgeRequired))
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no ca_bundle")
	}
}

func TestNewServerTLSConfig_PolicyFull_WithCABundle(t *testing.T) {
	pool := x509.NewCertPool()
	called := false
	fn := func(tls.ConnectionState) error {
		called = true
		return nil
	}
	cfg, err := NewServerTLSConfig(
		WithClientVerificationPolicy(PolicyFull),
		WithClientCA(pool),
		WithServerVerifyConnection(fn),
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
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection not set")
	}
	_ = called
}

func TestNewServerTLSConfig_PolicyFull_NoCABundle(t *testing.T) {
	fn := func(tls.ConnectionState) error { return nil }
	cfg, err := NewServerTLSConfig(
		WithClientVerificationPolicy(PolicyFull),
		WithServerVerifyConnection(fn),
	)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs should be nil when no ca_bundle")
	}
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection not set")
	}
}
