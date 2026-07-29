package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildServerOptions_PKIOnly(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "pki_only",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options (cert + verifier), got %d", len(opts))
	}
}

func TestBuildServerOptions_PKI(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "pki",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildServerOptions_None(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "none",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildServerOptions_Badge(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "badge",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildServerOptions_BadgeRequired(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "badge_required",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildServerOptions_DANE(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "dane",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildServerOptions_DANEAndBadge(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "dane_and_badge",
	}

	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
	}
}

func TestBuildServerOptions_WithCABundle(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		caBundle:   "/path/to/ca-bundle.pem",
		trustLevel: "badge",
	}

	opts := buildServerOptions(cfg)
	if len(opts) != 3 {
		t.Errorf("expected 3 options (cert + CA + verifier), got %d", len(opts))
	}
}

func TestBuildMux_HelloEndpoint(t *testing.T) {
	mux := buildMux()

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["message"] != "Hello from ATI agent server" {
		t.Errorf("unexpected message: %v", resp["message"])
	}
	if resp["method"] != "GET" {
		t.Errorf("unexpected method: %v", resp["method"])
	}
}

func TestBuildMux_EchoEndpoint(t *testing.T) {
	mux := buildMux()

	body := `{"key":"value"}`
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	echo, ok := resp["echo"].(map[string]any)
	if !ok {
		t.Fatal("expected echo to be an object")
	}
	if echo["key"] != "value" {
		t.Errorf("unexpected echo content: %v", echo)
	}
}

func TestBuildMux_EchoEndpoint_NoBody(t *testing.T) {
	mux := buildMux()

	req := httptest.NewRequest(http.MethodPost, "/echo", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestRunServer_InvalidCert(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "/nonexistent/cert.pem",
		keyFile:    "/nonexistent/key.pem",
		addr:       ":0",
		trustLevel: "pki_only",
	}

	err := runServer(cfg)
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
}
