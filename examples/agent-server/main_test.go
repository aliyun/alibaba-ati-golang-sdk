package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseServerFlagsFromArgs_Defaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := parseServerFlagsFromArgs(fs, []string{})

	if cfg.certFile != "server.crt" {
		t.Errorf("certFile = %q, want %q", cfg.certFile, "server.crt")
	}
	if cfg.keyFile != "server.key" {
		t.Errorf("keyFile = %q, want %q", cfg.keyFile, "server.key")
	}
	if cfg.caBundle != "" {
		t.Errorf("caBundle = %q, want empty", cfg.caBundle)
	}
	if cfg.addr != ":8443" {
		t.Errorf("addr = %q, want %q", cfg.addr, ":8443")
	}
	if cfg.trustLevel != "pki_only" {
		t.Errorf("trustLevel = %q, want %q", cfg.trustLevel, "pki_only")
	}
}

func TestParseServerFlagsFromArgs_Custom(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := parseServerFlagsFromArgs(fs, []string{
		"-cert", "my-server.crt",
		"-key", "my-server.key",
		"-ca", "/path/to/ca.pem",
		"-addr", ":9443",
		"-trust", "dane",
	})

	if cfg.certFile != "my-server.crt" {
		t.Errorf("certFile = %q, want %q", cfg.certFile, "my-server.crt")
	}
	if cfg.keyFile != "my-server.key" {
		t.Errorf("keyFile = %q, want %q", cfg.keyFile, "my-server.key")
	}
	if cfg.caBundle != "/path/to/ca.pem" {
		t.Errorf("caBundle = %q, want %q", cfg.caBundle, "/path/to/ca.pem")
	}
	if cfg.addr != ":9443" {
		t.Errorf("addr = %q, want %q", cfg.addr, ":9443")
	}
	if cfg.trustLevel != "dane" {
		t.Errorf("trustLevel = %q, want %q", cfg.trustLevel, "dane")
	}
}

func TestParseServerFlagsFromArgs_NilArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := parseServerFlagsFromArgs(fs, nil)
	if cfg.certFile != "server.crt" {
		t.Errorf("certFile = %q, want default", cfg.certFile)
	}
}

func TestBuildServerOptions_PKIOnly(t *testing.T) {
	cfg := &serverConfig{
		certFile:   "test.crt",
		keyFile:    "test.key",
		trustLevel: "pki_only",
	}
	opts := buildServerOptions(cfg)
	if len(opts) < 2 {
		t.Errorf("expected at least 2 options, got %d", len(opts))
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

func TestFormatServerStartup(t *testing.T) {
	cfg := &serverConfig{
		addr:       ":9443",
		trustLevel: "badge",
		certFile:   "server.crt",
	}
	result := formatServerStartup(cfg)
	if !strings.Contains(result, ":9443") {
		t.Errorf("expected addr in output, got %q", result)
	}
	if !strings.Contains(result, "badge") {
		t.Errorf("expected trust level in output, got %q", result)
	}
	if !strings.Contains(result, "server.crt") {
		t.Errorf("expected cert file in output, got %q", result)
	}
	if !strings.Contains(result, "/hello, /echo") {
		t.Errorf("expected endpoints in output, got %q", result)
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

func TestBuildMux_HelloEndpoint_WithTLS(t *testing.T) {
	mux := buildMux()

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	// Simulate a TLS connection with no peer certificates (no ati:// URI SAN)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Without valid TLS peer certs, PeerATIName will fail so no peer fields
	if resp["message"] != "Hello from ATI agent server" {
		t.Errorf("unexpected message: %v", resp["message"])
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

func TestRunServer_ValidCert_BadPort(t *testing.T) {
	certFile, keyFile := generateTestServerCert(t)
	cfg := &serverConfig{
		certFile:   certFile,
		keyFile:    keyFile,
		addr:       ":-1",
		trustLevel: "pki_only",
	}

	err := runServer(cfg)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	if !strings.Contains(err.Error(), "server failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func generateTestServerCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	atiURI, _ := url.Parse("ati://v1.0.0.server.example.com")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"server.example.com", "localhost"},
		URIs:         []*url.URL{atiURI},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)
	return
}
