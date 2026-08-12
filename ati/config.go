package ati

import (
	"log/slog"
	"sync"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// Config holds the global SDK configuration set via Init().
type Config struct {
	LocalHostname    string      // This agent's hostname
	IdentityCertFile string      // Path to identity certificate PEM
	IdentityKeyFile  string      // Path to identity private key PEM
	CARootFile       string      // Path to custom CA root certificate (optional, uses system CA if empty)
	TrustLevel       *TrustLevel // Trust level pointer; nil means "use default (PolicyEnhanced)"
	DNSServer        string      // DNS server for DANE/TLSA lookups (host or host:port). Empty = system resolver.
}

var (
	globalConfig *Config
	configMu     sync.RWMutex
)

// Init initializes the ATI SDK with global configuration.
// When TrustLevel is nil (not explicitly set), it defaults to PolicyEnhanced
// to preserve backward compatibility with the previous BadgeRequired default.
// To explicitly use PolicyBasic, pass a non-nil pointer: &PolicyBasic.
func Init(cfg Config) error {
	if cfg.TrustLevel == nil {
		defaultLevel := PolicyEnhanced
		cfg.TrustLevel = &defaultLevel
	}
	configMu.Lock()
	globalConfig = &cfg
	configMu.Unlock()
	return nil
}

// GetConfig returns the global SDK configuration. Returns nil if Init() has not been called.
func GetConfig() *Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig
}

// defaultDiscoveryResolver creates the DNS-based discovery resolver.
// Agent discovery uses DNS TXT `_ati` records via StandardDNSResolver.
func defaultDiscoveryResolver() (verify.DNSResolver, error) {
	resolver := verify.NewStandardDNSResolver()
	slog.Info("[discovery] using DNS TXT records")
	return resolver, nil
}

// globalDNSServer returns the DNS server configured via Init() for DANE/TLSA
// lookups, or an empty string when unset (meaning: use the system resolver).
func globalDNSServer() string {
	configMu.RLock()
	defer configMu.RUnlock()
	if globalConfig != nil {
		return globalConfig.DNSServer
	}
	return ""
}
