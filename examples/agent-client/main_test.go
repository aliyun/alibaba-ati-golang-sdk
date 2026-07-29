package main

import (
	"testing"
	"time"
)

func TestBuildClientOptions_PKIOnly(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "pki_only",
		timeout:    5 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_Badge(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "badge",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_DANE(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "dane",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_PKI(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "pki",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_BadgeRequired(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "badge_required",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestBuildClientOptions_DANEAndBadge(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		serverURL:  "https://example.com/test",
		trustLevel: "dane_and_badge",
		timeout:    10 * time.Second,
	}

	opts := buildClientOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options, got %d", len(opts))
	}
}

func TestRunClient_InvalidCert(t *testing.T) {
	cfg := &clientConfig{
		certFile:   "/nonexistent/cert.pem",
		keyFile:    "/nonexistent/key.pem",
		serverURL:  "https://example.com/test",
		trustLevel: "badge",
		timeout:    5 * time.Second,
	}

	err := runClient(cfg)
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
}
