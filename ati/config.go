package ati

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// Config holds the global SDK configuration set via Init().
type Config struct {
	AK               string     // Alibaba Cloud AccessKey ID (required for agent discovery)
	SK               string     // Alibaba Cloud AccessKey Secret (required for agent discovery)
	LocalHostname    string     // This agent's hostname
	IdentityCertFile string     // Path to identity certificate PEM
	IdentityKeyFile  string     // Path to identity private key PEM
	CARootFile       string     // Path to custom CA root certificate (optional, uses system CA if empty)
	TrustLevel       TrustLevel // Trust level (default: BadgeRequired)
	DNSServer        string     // DNS server for DANE/TLSA lookups (host or host:port). Empty = system resolver.
}

var (
	globalConfig *Config
	configMu     sync.RWMutex
)

// Init initializes the ATI SDK with global configuration.
// Must be called before creating any AgentClient with aliyun discovery.
func Init(cfg Config) error {
	if cfg.AK == "" {
		return fmt.Errorf("ati.Init: AK is required")
	}
	if cfg.SK == "" {
		return fmt.Errorf("ati.Init: SK is required")
	}
	if cfg.LocalHostname == "" {
		return fmt.Errorf("ati.Init: LocalHostname is required")
	}
	if cfg.IdentityCertFile == "" {
		return fmt.Errorf("ati.Init: IdentityCertFile is required")
	}
	if cfg.IdentityKeyFile == "" {
		return fmt.Errorf("ati.Init: IdentityKeyFile is required")
	}

	if cfg.TrustLevel == 0 {
		cfg.TrustLevel = BadgeRequired
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

// defaultDiscoveryResolver creates the Aliyun-based discovery resolver.
// Agent discovery is only supported via the Aliyun marketplace API; DNS TXT
// discovery is not supported. Credentials are read from the global config set
// via Init(), falling back to the ATI_AK/ATI_SK environment variables. If no
// credentials are available it returns an error — there is no DNS fallback.
func defaultDiscoveryResolver() (verify.DNSResolver, error) {
	ak, sk := "", ""

	configMu.RLock()
	if globalConfig != nil {
		ak = globalConfig.AK
		sk = globalConfig.SK
	}
	configMu.RUnlock()

	if ak == "" {
		ak = os.Getenv("ATI_AK")
	}
	if sk == "" {
		sk = os.Getenv("ATI_SK")
	}

	if ak == "" || sk == "" {
		return nil, fmt.Errorf("agent discovery requires Aliyun credentials: set them via ati.Init(Config{AK, SK}) or the ATI_AK/ATI_SK environment variables")
	}

	resolver, err := verify.NewAliyunATIDiscovery(verify.AliyunATIConfig{
		AccessKeyID:     ak,
		AccessKeySecret: sk,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create aliyun discovery client: %w", err)
	}
	slog.Info("[discovery] using aliyun API", "endpoint", "alidns.aliyuncs.com")
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
