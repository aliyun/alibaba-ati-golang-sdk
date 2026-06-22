package verify

import (
	"log/slog"
	"testing"
	"time"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify/scitt"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.dnsResolver == nil {
		t.Error("expected non-nil dnsResolver")
	}
	if cfg.tlogClient == nil {
		t.Error("expected non-nil tlogClient")
	}
	if cfg.cache != nil {
		t.Error("expected nil cache by default")
	}
	if cfg.failurePolicy != FailClosed {
		t.Errorf("expected FailClosed, got %v", cfg.failurePolicy)
	}
	if cfg.urlValidator == nil {
		t.Error("expected non-nil urlValidator by default")
	}
	if cfg.daneResolver != nil {
		t.Error("expected nil daneResolver by default")
	}
}

func TestWithDNSResolver(t *testing.T) {
	mock := NewMockDNSResolver()
	cfg := defaultConfig()
	WithDNSResolver(mock)(cfg)
	if cfg.dnsResolver != mock {
		t.Error("expected custom DNS resolver to be set")
	}
}

func TestWithTlogClient(t *testing.T) {
	mock := NewMockTransparencyLogClient()
	cfg := defaultConfig()
	WithTlogClient(mock)(cfg)
	if cfg.tlogClient != mock {
		t.Error("expected custom tlog client to be set")
	}
}

func TestWithCache(t *testing.T) {
	cache := NewBadgeCache(DefaultCacheConfig())
	cfg := defaultConfig()
	WithCache(cache)(cfg)
	if cfg.cache != cache {
		t.Error("expected cache to be set")
	}
}

func TestWithCacheConfig(t *testing.T) {
	cfg := defaultConfig()
	WithCacheConfig(DefaultCacheConfig())(cfg)
	if cfg.cache == nil {
		t.Error("expected cache to be created from config")
	}
}

func TestWithFailurePolicy(t *testing.T) {
	cfg := defaultConfig()
	WithFailurePolicy(FailOpen)(cfg)
	if cfg.failurePolicy != FailOpen {
		t.Errorf("expected FailOpen, got %v", cfg.failurePolicy)
	}
}

func TestWithFailurePolicyConfig(t *testing.T) {
	cfg := defaultConfig()
	policyCfg := FailurePolicyConfig{MaxStaleness: 30 * time.Minute}
	WithFailurePolicyConfig(policyCfg)(cfg)
	if cfg.failurePolicyConfig.MaxStaleness != 30*time.Minute {
		t.Errorf("expected MaxStaleness 30m, got %v", cfg.failurePolicyConfig.MaxStaleness)
	}
}

func TestWithTrustedRADomains(t *testing.T) {
	cfg := defaultConfig()
	WithTrustedRADomains([]string{"example.com", "test.com"})(cfg)
	if cfg.urlValidator == nil {
		t.Error("expected urlValidator to be set")
	}
}

func TestWithoutURLValidation(t *testing.T) {
	cfg := defaultConfig()
	WithoutURLValidation()(cfg)
	if cfg.urlValidator != nil {
		t.Error("expected urlValidator to be nil")
	}
}

func TestWithDANEResolver_Option(t *testing.T) {
	mock := NewMockDANEResolver()
	cfg := defaultConfig()
	WithDANEResolver(mock)(cfg)
	if cfg.daneResolver != mock {
		t.Error("expected DANE resolver to be set")
	}
}

func TestWithScittKeyLookup(t *testing.T) {
	store, _ := scitt.NewKeyStore(nil)
	cfg := defaultConfig()
	WithScittKeyLookup(store)(cfg)
	if cfg.scittKeyLookup != store {
		t.Error("expected scitt key lookup to be set")
	}
}

func TestWithClockSkewTolerance(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want time.Duration
	}{
		{
			name: "normal value",
			d:    5 * time.Minute,
			want: 5 * time.Minute,
		},
		{
			name: "negative clamped to zero",
			d:    -1 * time.Second,
			want: 0,
		},
		{
			name: "exceeds max clamped to 10 minutes",
			d:    15 * time.Minute,
			want: 10 * time.Minute,
		},
		{
			name: "zero stays zero",
			d:    0,
			want: 0,
		},
		{
			name: "exactly 10 minutes allowed",
			d:    10 * time.Minute,
			want: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			WithClockSkewTolerance(tt.d)(cfg)
			if cfg.clockSkewTolerance != tt.want {
				t.Errorf("expected %v, got %v", tt.want, cfg.clockSkewTolerance)
			}
		})
	}
}

func TestWithLogger(t *testing.T) {
	logger := slog.Default()
	cfg := defaultConfig()
	WithLogger(logger)(cfg)
	if cfg.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestDefaultClockSkewTolerance(t *testing.T) {
	cfg := defaultConfig()
	if cfg.clockSkewTolerance != 120*time.Second {
		t.Errorf("expected default 120s, got %v", cfg.clockSkewTolerance)
	}
}

func TestDefaultScittKeyLookupNil(t *testing.T) {
	cfg := defaultConfig()
	if cfg.scittKeyLookup != nil {
		t.Error("expected nil scitt key lookup by default")
	}
}

func TestWithTrustedTLHost(t *testing.T) {
	cfg := defaultConfig()
	WithTrustedTLHost("custom.host:8180")(cfg)
	if cfg.trustedTLHost != "custom.host:8180" {
		t.Errorf("expected custom.host:8180, got %q", cfg.trustedTLHost)
	}
}

func TestWithTrustPolicy(t *testing.T) {
	tp := &TrustPolicy{TrustedIssuers: []string{"issuer1"}, MinKeyStrength: 2048}
	cfg := defaultConfig()
	WithTrustPolicy(tp)(cfg)
	if cfg.trustPolicy != tp {
		t.Error("expected trust policy to be set")
	}
	if len(cfg.trustPolicy.TrustedIssuers) != 1 || cfg.trustPolicy.TrustedIssuers[0] != "issuer1" {
		t.Error("trust policy content mismatch")
	}
}

func TestWithProducerKeys(t *testing.T) {
	cfg := defaultConfig()
	if cfg.producerKeys != nil {
		t.Error("expected nil producerKeys by default")
	}
}

func TestWithAgentCardVerifier(t *testing.T) {
	acv := &AgentCardVerifier{TrustedIssuers: []string{"iss1"}}
	cfg := defaultConfig()
	WithAgentCardVerifier(acv)(cfg)
	if cfg.agentCardVerifier != acv {
		t.Error("expected agent card verifier to be set")
	}
}

func TestWithSessionMonitor(t *testing.T) {
	sm := &SessionMonitor{PollInterval: 30}
	cfg := defaultConfig()
	WithSessionMonitor(sm)(cfg)
	if cfg.sessionMonitor != sm {
		t.Error("expected session monitor to be set")
	}
}

func TestWithOCSPCheckerOption(t *testing.T) {
	checker := &OCSPChecker{}
	cfg := defaultConfig()
	WithOCSPCheckerOption(checker)(cfg)
	if cfg.ocspChecker != checker {
		t.Error("expected OCSP checker to be set")
	}
}

func TestWithParallelFetch(t *testing.T) {
	cfg := defaultConfig()
	if cfg.parallelFetch {
		t.Error("expected parallelFetch false by default")
	}
	WithParallelFetch(true)(cfg)
	if !cfg.parallelFetch {
		t.Error("expected parallelFetch true after setting")
	}
	WithParallelFetch(false)(cfg)
	if cfg.parallelFetch {
		t.Error("expected parallelFetch false after unsetting")
	}
}

func TestWithOfflineMode(t *testing.T) {
	cfg := defaultConfig()
	if cfg.offlineMode {
		t.Error("expected offlineMode false by default")
	}
	WithOfflineMode(true)(cfg)
	if !cfg.offlineMode {
		t.Error("expected offlineMode true after setting")
	}
}

func TestWithTLBaseURL(t *testing.T) {
	cfg := defaultConfig()
	if cfg.tlBaseURL != DefaultTLBaseURL {
		t.Errorf("expected default TL base URL %q, got %q", DefaultTLBaseURL, cfg.tlBaseURL)
	}
	WithTLBaseURL("https://custom-tl.example.com")(cfg)
	if cfg.tlBaseURL != "https://custom-tl.example.com" {
		t.Errorf("expected custom URL, got %q", cfg.tlBaseURL)
	}
	WithTLBaseURL("")(cfg)
	if cfg.tlBaseURL != "" {
		t.Errorf("expected empty URL, got %q", cfg.tlBaseURL)
	}
}

func TestWithVerificationPolicy(t *testing.T) {
	cfg := defaultConfig()
	WithVerificationPolicy(ati.PolicyPKI)(cfg)
	if cfg.verificationPolicy != ati.PolicyPKI {
		t.Errorf("expected PolicyPKI, got %v", cfg.verificationPolicy)
	}
	WithVerificationPolicy(ati.PolicyPKIBadgeDANE)(cfg)
	if cfg.verificationPolicy != ati.PolicyPKIBadgeDANE {
		t.Errorf("expected PolicyPKIBadgeDANE, got %v", cfg.verificationPolicy)
	}
}
