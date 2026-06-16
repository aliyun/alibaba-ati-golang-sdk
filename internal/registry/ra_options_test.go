package registry

import (
	"testing"
)

func TestDefaultRAConfig(t *testing.T) {
	cfg := defaultRAConfig()
	if cfg.endpoint != "https://ra.ansagent.cn:8180/ans/api/v1" {
		t.Errorf("default endpoint = %q, want https://ra.ansagent.cn:8180/ans/api/v1", cfg.endpoint)
	}
	if cfg.accessKeyID != "" {
		t.Errorf("default accessKeyID = %q, want empty", cfg.accessKeyID)
	}
	if cfg.accessKeySecret != "" {
		t.Errorf("default accessKeySecret = %q, want empty", cfg.accessKeySecret)
	}
}

func TestWithAccessKeyID(t *testing.T) {
	cfg := defaultRAConfig()
	WithAccessKeyID("test-ak-id")(cfg)
	if cfg.accessKeyID != "test-ak-id" {
		t.Errorf("accessKeyID = %q, want test-ak-id", cfg.accessKeyID)
	}
}

func TestWithAccessKeySecret(t *testing.T) {
	cfg := defaultRAConfig()
	WithAccessKeySecret("test-ak-secret")(cfg)
	if cfg.accessKeySecret != "test-ak-secret" {
		t.Errorf("accessKeySecret = %q, want test-ak-secret", cfg.accessKeySecret)
	}
}

func TestWithRAEndpoint(t *testing.T) {
	cfg := defaultRAConfig()
	WithRAEndpoint("https://custom.example.com/api")(cfg)
	if cfg.endpoint != "https://custom.example.com/api" {
		t.Errorf("endpoint = %q, want https://custom.example.com/api", cfg.endpoint)
	}
}

func TestWithListLimit(t *testing.T) {
	cfg := &listConfig{}
	WithListLimit(50)(cfg)
	if cfg.limit != 50 {
		t.Errorf("limit = %d, want 50", cfg.limit)
	}
}

func TestWithListOffset(t *testing.T) {
	cfg := &listConfig{}
	WithListOffset(10)(cfg)
	if cfg.offset != 10 {
		t.Errorf("offset = %d, want 10", cfg.offset)
	}
}

func TestWithListHost(t *testing.T) {
	cfg := &listConfig{}
	WithListHost("agent.example.com")(cfg)
	if cfg.host != "agent.example.com" {
		t.Errorf("host = %q, want agent.example.com", cfg.host)
	}
}

func TestWithAuditLimit(t *testing.T) {
	cfg := &auditConfig{}
	WithAuditLimit(100)(cfg)
	if cfg.limit != 100 {
		t.Errorf("limit = %d, want 100", cfg.limit)
	}
}

func TestWithAuditOffset(t *testing.T) {
	cfg := &auditConfig{}
	WithAuditOffset(5)(cfg)
	if cfg.offset != 5 {
		t.Errorf("offset = %d, want 5", cfg.offset)
	}
}
