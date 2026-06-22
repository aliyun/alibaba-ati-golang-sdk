package registry

import (
	"testing"
)

func TestDefaultRAConfig(t *testing.T) {
	cfg := defaultRAConfig()
	if cfg.endpoint != "alidns.aliyuncs.com" {
		t.Errorf("default endpoint = %q, want alidns.aliyuncs.com", cfg.endpoint)
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
	WithRAEndpoint("alidns.cn-hangzhou.aliyuncs.com")(cfg)
	if cfg.endpoint != "alidns.cn-hangzhou.aliyuncs.com" {
		t.Errorf("endpoint = %q, want alidns.cn-hangzhou.aliyuncs.com", cfg.endpoint)
	}
}
