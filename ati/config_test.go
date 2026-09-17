package ati

import (
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// resetGlobalConfig clears the package-level globalConfig so tests start clean.
func resetGlobalConfig() {
	configMu.Lock()
	globalConfig = nil
	configMu.Unlock()
}

func TestInit_DefaultTrustLevel(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	cfg := Config{} // TrustLevel == nil; Init elevates to PolicyEnhanced for backward compat
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	got := GetConfig()
	if got == nil {
		t.Fatal("GetConfig() = nil after Init")
	}
	if got.TrustLevel == nil || *got.TrustLevel != PolicyEnhanced {
		t.Errorf("TrustLevel = %v, want %s (nil elevated to PolicyEnhanced)", got.TrustLevel, PolicyEnhanced)
	}
}

func TestInit_ExplicitTrustLevel(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	level := PolicyAdvanced
	cfg := Config{TrustLevel: &level}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	got := GetConfig()
	if got == nil {
		t.Fatal("GetConfig() = nil after Init")
	}
	if got.TrustLevel == nil || *got.TrustLevel != PolicyAdvanced {
		t.Errorf("TrustLevel = %v, want %s (PolicyAdvanced)", got.TrustLevel, PolicyAdvanced)
	}
}

func TestInit_ExplicitPolicyBasic(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	// Explicitly setting PolicyBasic via pointer should be preserved (not elevated)
	level := PolicyBasic
	cfg := Config{TrustLevel: &level}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	got := GetConfig()
	if got == nil {
		t.Fatal("GetConfig() = nil after Init")
	}
	if got.TrustLevel == nil || *got.TrustLevel != PolicyBasic {
		t.Errorf("TrustLevel = %v, want %s (explicit PolicyBasic preserved)", got.TrustLevel, PolicyBasic)
	}
}

func TestGetConfig_BeforeInit(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	if got := GetConfig(); got != nil {
		t.Errorf("GetConfig() before Init = %v, want nil", got)
	}
}

func TestGetConfig_AfterInit(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	cfg := Config{LocalHostname: "agent.example.com"}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	got := GetConfig()
	if got == nil {
		t.Fatal("GetConfig() = nil after Init")
	}
	if got.LocalHostname != "agent.example.com" {
		t.Errorf("LocalHostname = %q, want %q", got.LocalHostname, "agent.example.com")
	}
}

func TestGetConfig_PreservesAllFields(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	level := DANEAndBadge
	cfg := Config{
		LocalHostname:    "host.example.com",
		IdentityCertFile: "/path/to/cert.pem",
		IdentityKeyFile:  "/path/to/key.pem",
		CARootFile:       "/path/to/ca.pem",
		TrustLevel:       &level,
		DNSServer:        "8.8.8.8:53",
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	got := GetConfig()
	if got == nil {
		t.Fatal("GetConfig() = nil after Init")
	}
	if got.LocalHostname != cfg.LocalHostname {
		t.Errorf("LocalHostname = %q, want %q", got.LocalHostname, cfg.LocalHostname)
	}
	if got.IdentityCertFile != cfg.IdentityCertFile {
		t.Errorf("IdentityCertFile = %q, want %q", got.IdentityCertFile, cfg.IdentityCertFile)
	}
	if got.IdentityKeyFile != cfg.IdentityKeyFile {
		t.Errorf("IdentityKeyFile = %q, want %q", got.IdentityKeyFile, cfg.IdentityKeyFile)
	}
	if got.CARootFile != cfg.CARootFile {
		t.Errorf("CARootFile = %q, want %q", got.CARootFile, cfg.CARootFile)
	}
	if got.TrustLevel == nil || *got.TrustLevel != *cfg.TrustLevel {
		t.Errorf("TrustLevel = %v, want %v", got.TrustLevel, cfg.TrustLevel)
	}
	if got.DNSServer != cfg.DNSServer {
		t.Errorf("DNSServer = %q, want %q", got.DNSServer, cfg.DNSServer)
	}
}

func TestGlobalDNSServer_BeforeInit(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	if got := globalDNSServer(); got != "" {
		t.Errorf("globalDNSServer() before Init = %q, want empty", got)
	}
}

func TestGlobalDNSServer_AfterInitEmpty(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	cfg := Config{DNSServer: ""}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if got := globalDNSServer(); got != "" {
		t.Errorf("globalDNSServer() = %q, want empty", got)
	}
}

func TestGlobalDNSServer_AfterInitSet(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	cfg := Config{DNSServer: "1.1.1.1:53"}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if got := globalDNSServer(); got != "1.1.1.1:53" {
		t.Errorf("globalDNSServer() = %q, want %q", got, "1.1.1.1:53")
	}
}

func TestGlobalDNSServer_AfterInitHostOnly(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	cfg := Config{DNSServer: "8.8.8.8"}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if got := globalDNSServer(); got != "8.8.8.8" {
		t.Errorf("globalDNSServer() = %q, want %q", got, "8.8.8.8")
	}
}

func TestDefaultDiscoveryResolver(t *testing.T) {
	resolver, err := defaultDiscoveryResolver()
	if err != nil {
		t.Fatalf("defaultDiscoveryResolver() error = %v", err)
	}
	if resolver == nil {
		t.Fatal("defaultDiscoveryResolver() = nil, want non-nil resolver")
	}
}

func TestDefaultDiscoveryResolver_ImplementsDNSResolver(t *testing.T) {
	resolver, err := defaultDiscoveryResolver()
	if err != nil {
		t.Fatalf("defaultDiscoveryResolver() error = %v", err)
	}

	// Verify the returned resolver satisfies the DNSResolver interface.
	var _ verify.DNSResolver = resolver
}

func TestInit_DoesNotMutateOriginalConfig(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	original := Config{TrustLevel: nil} // nil → will be elevated to PolicyEnhanced
	if err := Init(original); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// The caller's struct should not have been mutated (Init takes by value).
	if original.TrustLevel != nil {
		t.Errorf("Init mutated the caller's Config: TrustLevel = %v, want nil", original.TrustLevel)
	}

	// The stored global config has nil elevated to PolicyEnhanced.
	got := GetConfig()
	if got == nil {
		t.Fatal("GetConfig() = nil after Init")
	}
	if got.TrustLevel == nil || *got.TrustLevel != PolicyEnhanced {
		t.Errorf("stored TrustLevel = %v, want %s", got.TrustLevel, PolicyEnhanced)
	}
}

func TestInit_OverwritesPreviousConfig(t *testing.T) {
	resetGlobalConfig()
	defer resetGlobalConfig()

	first := Config{LocalHostname: "first.example.com"} // TrustLevel nil → PolicyEnhanced
	if err := Init(first); err != nil {
		t.Fatalf("Init(first) error = %v", err)
	}
	if got := GetConfig(); got.LocalHostname != "first.example.com" {
		t.Fatalf("first Init: LocalHostname = %q, want %q", got.LocalHostname, "first.example.com")
	}

	level := PolicyAdvanced
	second := Config{LocalHostname: "second.example.com", TrustLevel: &level}
	if err := Init(second); err != nil {
		t.Fatalf("Init(second) error = %v", err)
	}
	got := GetConfig()
	if got.LocalHostname != "second.example.com" {
		t.Errorf("second Init: LocalHostname = %q, want %q", got.LocalHostname, "second.example.com")
	}
	if got.TrustLevel == nil || *got.TrustLevel != PolicyAdvanced {
		t.Errorf("second Init: TrustLevel = %v, want %s", got.TrustLevel, PolicyAdvanced)
	}
}
