package verify

import (
	"log/slog"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify/scitt"
)

// Option configures a verifier.
type Option func(*verifierConfig)

// verifierConfig holds the configuration for verifiers.
type verifierConfig struct {
	dnsResolver         DNSResolver
	tlogClient          TransparencyLogClient
	cache               *BadgeCache
	failurePolicy       FailurePolicy
	failurePolicyConfig FailurePolicyConfig
	trustedTLHost       string
	daneResolver        DANEResolver
	scittKeyLookup      scitt.KeyLookup
	clockSkewTolerance  time.Duration
	logger              *slog.Logger

	// Extended verification options (spec §9.4)
	trustPolicy      *TrustPolicy
	producerKeys     ProducerKeyLookup
	agentCardVerifier *AgentCardVerifier
	sessionMonitor   *SessionMonitor
	ocspChecker      *OCSPChecker
	parallelFetch    bool
	offlineMode      bool
}

// defaultClockSkewTolerance is the default maximum allowed clock skew (120 seconds).
const defaultClockSkewTolerance = 120 * time.Second

// DefaultTrustedTLHost is the trusted Transparency Log hostname used as
// the trust anchor for badge URL rewriting. Badge TXT records may contain
// arbitrary hostnames; the SDK replaces them with this value before fetching.
const DefaultTrustedTLHost = "tl.atiagent.cn"

// defaultConfig returns the default verifier configuration.
func defaultConfig() *verifierConfig {
	return &verifierConfig{
		dnsResolver:         NewStandardDNSResolver(),
		tlogClient:          NewHTTPTransparencyLogClient(),
		cache:               nil,
		failurePolicy:       FailClosed,
		failurePolicyConfig: DefaultFailurePolicyConfig(),
		trustedTLHost:       "",
		clockSkewTolerance:  defaultClockSkewTolerance,
	}
}

// WithDNSResolver sets a custom DNS resolver.
func WithDNSResolver(r DNSResolver) Option {
	return func(c *verifierConfig) {
		c.dnsResolver = r
	}
}

// WithTlogClient sets a custom transparency log client.
func WithTlogClient(t TransparencyLogClient) Option {
	return func(c *verifierConfig) {
		c.tlogClient = t
	}
}

// WithCache sets a badge cache.
func WithCache(cache *BadgeCache) Option {
	return func(c *verifierConfig) {
		c.cache = cache
	}
}

// WithCacheConfig creates and sets a badge cache with the given configuration.
func WithCacheConfig(cfg CacheConfig) Option {
	return func(c *verifierConfig) {
		c.cache = NewBadgeCache(cfg)
	}
}

// WithFailurePolicy sets the failure policy for DNS/TLog errors.
//
// NOTE: This policy does NOT apply to SCITT verification failures — a malformed
// or signature-invalid SCITT artifact is always terminal, regardless of FailOpen
// settings, to prevent forgery acceptance. Only DNS and TLog infrastructure
// failures are subject to this policy.
func WithFailurePolicy(policy FailurePolicy) Option {
	return func(c *verifierConfig) {
		c.failurePolicy = policy
	}
}

// WithFailurePolicyConfig sets the failure policy configuration.
func WithFailurePolicyConfig(cfg FailurePolicyConfig) Option {
	return func(c *verifierConfig) {
		c.failurePolicyConfig = cfg
	}
}

// WithTrustedRADomains is a no-op retained for backward compatibility.
// URL domain validation has been removed; hostname rewriting via
// DefaultTrustedTLHost provides equivalent protection.
func WithTrustedRADomains(_ []string) Option {
	return func(_ *verifierConfig) {}
}

// WithoutURLValidation is a no-op retained for backward compatibility.
func WithoutURLValidation() Option {
	return func(_ *verifierConfig) {}
}

// WithTrustedTLHost overrides the trusted Transparency Log hostname used for
// badge URL rewriting. The default is DefaultTrustedTLHost.
func WithTrustedTLHost(host string) Option {
	return func(c *verifierConfig) {
		c.trustedTLHost = host
	}
}

// WithDANEResolver enables DANE/TLSA verification using the given resolver.
// When set, the verifier performs an additional DANE check after badge verification.
// DANE rejection (fingerprint mismatch or DNSSEC failure) overrides a successful badge check.
func WithDANEResolver(d DANEResolver) Option {
	return func(c *verifierConfig) {
		c.daneResolver = d
	}
}

// WithScittKeyLookup enables SCITT verification using the given key store.
// When set, VerifyWithScitt methods can verify SCITT receipts and status tokens.
func WithScittKeyLookup(kl scitt.KeyLookup) Option {
	return func(c *verifierConfig) {
		c.scittKeyLookup = kl
	}
}

// WithClockSkewTolerance sets the maximum allowed clock skew for status token expiry checks.
// Negative values are clamped to 0. Values exceeding 10 minutes are clamped to 10 minutes.
// Default is 120 seconds.
func WithClockSkewTolerance(d time.Duration) Option {
	return func(c *verifierConfig) {
		if d < 0 {
			d = 0
		}
		const maxSkew = 10 * time.Minute
		if d > maxSkew {
			d = maxSkew
		}
		c.clockSkewTolerance = d
	}
}

// WithLogger sets a structured logger for verification operations.
// When nil, slog.Default() is used.
func WithLogger(l *slog.Logger) Option {
	return func(c *verifierConfig) {
		c.logger = l
	}
}

// WithTrustPolicy sets the trust policy for verification decisions per spec §9.4.
func WithTrustPolicy(tp *TrustPolicy) Option {
	return func(c *verifierConfig) {
		c.trustPolicy = tp
	}
}

// WithProducerKeys sets the producer key lookup for verifying producer signatures.
func WithProducerKeys(keys ProducerKeyLookup) Option {
	return func(c *verifierConfig) {
		c.producerKeys = keys
	}
}

// WithAgentCardVerifier enables Agent Card verification with the given verifier.
func WithAgentCardVerifier(v *AgentCardVerifier) Option {
	return func(c *verifierConfig) {
		c.agentCardVerifier = v
	}
}

// WithSessionMonitor enables long-connection session monitoring.
func WithSessionMonitor(sm *SessionMonitor) Option {
	return func(c *verifierConfig) {
		c.sessionMonitor = sm
	}
}

// WithOCSPChecker enables OCSP revocation checking.
func WithOCSPCheckerOption(checker *OCSPChecker) Option {
	return func(c *verifierConfig) {
		c.ocspChecker = checker
	}
}

// WithParallelFetch enables parallel DNS and TL fetching.
func WithParallelFetch(enabled bool) Option {
	return func(c *verifierConfig) {
		c.parallelFetch = enabled
	}
}

// WithOfflineMode enables offline/self-contained verification mode.
func WithOfflineMode(enabled bool) Option {
	return func(c *verifierConfig) {
		c.offlineMode = enabled
	}
}
