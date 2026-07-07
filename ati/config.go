package ati

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"
)

// Config holds the global SDK configuration set via Init().
type Config struct {
	AK               string     // Alibaba Cloud AccessKey ID
	SK               string     // Alibaba Cloud AccessKey Secret
	Endpoint         string     // Aliyun API endpoint (default: "alidns.aliyuncs.com")
	LocalHostname    string     // This agent's hostname
	IdentityCertFile string     // Path to identity certificate PEM
	IdentityKeyFile  string     // Path to identity private key PEM
	CARootFile       string     // Path to custom CA root certificate (optional, uses system CA if empty)
	TrustLevel       TrustLevel // Trust level (default: TrustPKI)
	TLBaseURL        string     // Transparency Log base URL (default: "https://tl.atiagent.cn:8180")
	DNSServer        string     // DANE DNS server (only for TrustFull)
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

	if cfg.Endpoint == "" {
		cfg.Endpoint = "alidns.aliyuncs.com"
	}
	if cfg.TLBaseURL == "" {
		cfg.TLBaseURL = "https://tl.atiagent.cn:8180"
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

// defaultDiscoveryResolver creates the default discovery resolver.
// Priority: global config AK/SK → env ATI_AK/ATI_SK → fallback to DNS.
func defaultDiscoveryResolver() verify.DNSResolver {
	ak, sk, endpoint := "", "", "alidns.aliyuncs.com"

	configMu.RLock()
	if globalConfig != nil {
		ak = globalConfig.AK
		sk = globalConfig.SK
		if globalConfig.Endpoint != "" {
			endpoint = globalConfig.Endpoint
		}
	}
	configMu.RUnlock()

	if ak == "" {
		ak = os.Getenv("ATI_AK")
	}
	if sk == "" {
		sk = os.Getenv("ATI_SK")
	}

	if ak != "" && sk != "" {
		resolver, err := verify.NewAliyunATIDiscovery(verify.AliyunATIConfig{
			AccessKeyID:     ak,
			AccessKeySecret: sk,
			Endpoint:        endpoint,
		})
		if err == nil {
			slog.Info("[discovery] using aliyun API", "endpoint", endpoint)
			return resolver
		}
		slog.Warn("[discovery] failed to create aliyun client, falling back to DNS", "error", err)
	} else {
		slog.Warn("[discovery] ATI_AK/ATI_SK not set, falling back to DNS _ati TXT")
	}

	return verify.NewStandardDNSResolver()
}
