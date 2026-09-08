package verify

import (
	"log/slog"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/verify/scitt"
)

// TestExtraOption_NonPanic exercises each option function to cover its body.
// Because verifierConfig is unexported, we apply options via defaultConfig()
// (same pattern as the existing options_test.go) and additionally verify
// integration through NewServerVerifier/NewClientVerifier to ensure the
// options are actually invoked by the public constructors.

func TestExtra_WithTrustedRADomains(t *testing.T) {
	t.Run("via config", func(t *testing.T) {
		cfg := defaultConfig()
		WithTrustedRADomains([]string{"a.example", "b.example"})(cfg)
		// no-op: nothing to assert except no panic
	})
	t.Run("via NewServerVerifier", func(t *testing.T) {
		v := NewServerVerifier(WithTrustedRADomains(nil))
		if v == nil {
			t.Fatal("NewServerVerifier returned nil")
		}
	})
	t.Run("via NewClientVerifier", func(t *testing.T) {
		v := NewClientVerifier(WithTrustedRADomains([]string{"x"}))
		if v == nil {
			t.Fatal("NewClientVerifier returned nil")
		}
	})
}

func TestExtra_WithoutURLValidation(t *testing.T) {
	t.Run("via config", func(t *testing.T) {
		cfg := defaultConfig()
		WithoutURLValidation()(cfg)
	})
	t.Run("via NewServerVerifier", func(t *testing.T) {
		v := NewServerVerifier(WithoutURLValidation())
		if v == nil {
			t.Fatal("NewServerVerifier returned nil")
		}
	})
}

func TestExtra_WithTrustedTLHost(t *testing.T) {
	t.Run("sets trustedTLHost on config", func(t *testing.T) {
		cfg := defaultConfig()
		WithTrustedTLHost("custom.host")(cfg)
		if cfg.trustedTLHost != "custom.host" {
			t.Errorf("trustedTLHost = %q, want %q", cfg.trustedTLHost, "custom.host")
		}
	})
	t.Run("default is empty string", func(t *testing.T) {
		cfg := defaultConfig()
		if cfg.trustedTLHost != "" {
			t.Errorf("default trustedTLHost = %q, want empty", cfg.trustedTLHost)
		}
	})
	t.Run("via NewClientVerifier", func(t *testing.T) {
		v := NewClientVerifier(WithTrustedTLHost("custom.host"))
		if v == nil {
			t.Fatal("NewClientVerifier returned nil")
		}
	})
}

func TestExtra_WithDANEResolver(t *testing.T) {
	t.Run("sets daneResolver on config", func(t *testing.T) {
		mock := NewMockDANEResolver()
		cfg := defaultConfig()
		WithDANEResolver(mock)(cfg)
		if cfg.daneResolver != mock {
			t.Error("expected daneResolver to be set to mock")
		}
	})
	t.Run("via NewServerVerifier", func(t *testing.T) {
		v := NewServerVerifier(WithDANEResolver(NewMockDANEResolver()))
		if v == nil {
			t.Fatal("NewServerVerifier returned nil")
		}
	})
}

func TestExtra_WithScittKeyLookup(t *testing.T) {
	t.Run("sets scittKeyLookup on config", func(t *testing.T) {
		store, err := scitt.NewKeyStore(nil)
		if err != nil {
			t.Fatalf("NewKeyStore() error = %v", err)
		}
		cfg := defaultConfig()
		WithScittKeyLookup(store)(cfg)
		if cfg.scittKeyLookup != store {
			t.Error("expected scittKeyLookup to be set")
		}
	})
}

func TestExtra_WithClockSkewTolerance_Clamp(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want time.Duration
	}{
		{"negative clamped to zero", -1 * time.Second, 0},
		{"exceeds 10min clamped to 10min", 20 * time.Minute, 10 * time.Minute},
		{"5min preserved", 5 * time.Minute, 5 * time.Minute},
		{"zero preserved", 0, 0},
		{"exactly 10min preserved", 10 * time.Minute, 10 * time.Minute},
		{"just under 10min preserved", 9*time.Minute + 59*time.Second, 9*time.Minute + 59*time.Second},
		{"just over 10min clamped", 10*time.Minute + time.Second, 10 * time.Minute},
		{"huge negative clamped", -24 * time.Hour, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			WithClockSkewTolerance(tt.d)(cfg)
			if cfg.clockSkewTolerance != tt.want {
				t.Errorf("clockSkewTolerance = %v, want %v", cfg.clockSkewTolerance, tt.want)
			}
		})
	}
}

func TestExtra_WithLogger(t *testing.T) {
	t.Run("sets logger on config", func(t *testing.T) {
		logger := slog.Default()
		cfg := defaultConfig()
		WithLogger(logger)(cfg)
		if cfg.logger != logger {
			t.Error("expected logger to be set")
		}
	})
	t.Run("nil logger accepted without panic", func(t *testing.T) {
		cfg := defaultConfig()
		WithLogger(nil)(cfg)
	})
	t.Run("via NewServerVerifier", func(t *testing.T) {
		v := NewServerVerifier(WithLogger(slog.Default()))
		if v == nil {
			t.Fatal("NewServerVerifier returned nil")
		}
	})
}

func TestExtra_WithTrustPolicy(t *testing.T) {
	t.Run("nil trust policy accepted without panic", func(t *testing.T) {
		cfg := defaultConfig()
		WithTrustPolicy(nil)(cfg)
		if cfg.trustPolicy != nil {
			t.Error("expected trustPolicy to be nil")
		}
	})
	t.Run("non-nil trust policy set", func(t *testing.T) {
		tp := &TrustPolicy{}
		cfg := defaultConfig()
		WithTrustPolicy(tp)(cfg)
		if cfg.trustPolicy != tp {
			t.Error("expected trustPolicy to be set")
		}
	})
}

func TestExtra_WithProducerKeys(t *testing.T) {
	t.Run("sets producerKeys on config", func(t *testing.T) {
		mock := NewMockProducerKeyLookup()
		cfg := defaultConfig()
		WithProducerKeys(mock)(cfg)
		if cfg.producerKeys != mock {
			t.Error("expected producerKeys to be set")
		}
	})
	t.Run("nil accepted without panic", func(t *testing.T) {
		cfg := defaultConfig()
		WithProducerKeys(nil)(cfg)
		if cfg.producerKeys != nil {
			t.Error("expected producerKeys to be nil")
		}
	})
}

func TestExtra_WithAgentCardVerifier(t *testing.T) {
	t.Run("nil accepted without panic", func(t *testing.T) {
		cfg := defaultConfig()
		WithAgentCardVerifier(nil)(cfg)
		if cfg.agentCardVerifier != nil {
			t.Error("expected agentCardVerifier to be nil")
		}
	})
	t.Run("non-nil agent card verifier set", func(t *testing.T) {
		acv := &AgentCardVerifier{}
		cfg := defaultConfig()
		WithAgentCardVerifier(acv)(cfg)
		if cfg.agentCardVerifier != acv {
			t.Error("expected agentCardVerifier to be set")
		}
	})
}

func TestExtra_WithSessionMonitor(t *testing.T) {
	t.Run("nil accepted without panic", func(t *testing.T) {
		cfg := defaultConfig()
		WithSessionMonitor(nil)(cfg)
		if cfg.sessionMonitor != nil {
			t.Error("expected sessionMonitor to be nil")
		}
	})
	t.Run("non-nil session monitor set", func(t *testing.T) {
		sm := &SessionMonitor{}
		cfg := defaultConfig()
		WithSessionMonitor(sm)(cfg)
		if cfg.sessionMonitor != sm {
			t.Error("expected sessionMonitor to be set")
		}
	})
}

func TestExtra_WithOCSPCheckerOption(t *testing.T) {
	t.Run("nil accepted without panic", func(t *testing.T) {
		cfg := defaultConfig()
		WithOCSPCheckerOption(nil)(cfg)
		if cfg.ocspChecker != nil {
			t.Error("expected ocspChecker to be nil")
		}
	})
	t.Run("non-nil ocsp checker set", func(t *testing.T) {
		oc := &OCSPChecker{}
		cfg := defaultConfig()
		WithOCSPCheckerOption(oc)(cfg)
		if cfg.ocspChecker != oc {
			t.Error("expected ocspChecker to be set")
		}
	})
}

func TestExtra_WithParallelFetch(t *testing.T) {
	t.Run("enabled true", func(t *testing.T) {
		cfg := defaultConfig()
		WithParallelFetch(true)(cfg)
		if !cfg.parallelFetch {
			t.Error("expected parallelFetch to be true")
		}
	})
	t.Run("enabled false", func(t *testing.T) {
		cfg := defaultConfig()
		WithParallelFetch(false)(cfg)
		if cfg.parallelFetch {
			t.Error("expected parallelFetch to be false")
		}
	})
	t.Run("via NewServerVerifier", func(t *testing.T) {
		v := NewServerVerifier(WithParallelFetch(true))
		if v == nil {
			t.Fatal("NewServerVerifier returned nil")
		}
	})
}

func TestExtra_WithOfflineMode(t *testing.T) {
	t.Run("enabled true", func(t *testing.T) {
		cfg := defaultConfig()
		WithOfflineMode(true)(cfg)
		if !cfg.offlineMode {
			t.Error("expected offlineMode to be true")
		}
	})
	t.Run("enabled false", func(t *testing.T) {
		cfg := defaultConfig()
		WithOfflineMode(false)(cfg)
		if cfg.offlineMode {
			t.Error("expected offlineMode to be false")
		}
	})
	t.Run("via NewClientVerifier", func(t *testing.T) {
		v := NewClientVerifier(WithOfflineMode(true))
		if v == nil {
			t.Fatal("NewClientVerifier returned nil")
		}
	})
}

// TestExtra_MultipleOptionsCombined ensures all options can be applied together
// through the public constructor without panic.
func TestExtra_MultipleOptionsCombined(t *testing.T) {
	store, _ := scitt.NewKeyStore(nil)
	v := NewServerVerifier(
		WithTrustedRADomains([]string{"a"}),
		WithoutURLValidation(),
		WithTrustedTLHost("tl.example"),
		WithDANEResolver(NewMockDANEResolver()),
		WithScittKeyLookup(store),
		WithClockSkewTolerance(5*time.Minute),
		WithLogger(slog.Default()),
		WithTrustPolicy(&TrustPolicy{}),
		WithProducerKeys(NewMockProducerKeyLookup()),
		WithAgentCardVerifier(&AgentCardVerifier{}),
		WithSessionMonitor(&SessionMonitor{}),
		WithOCSPCheckerOption(&OCSPChecker{}),
		WithParallelFetch(true),
		WithOfflineMode(false),
	)
	if v == nil {
		t.Fatal("NewServerVerifier returned nil with combined options")
	}

	// Also exercise via NewClientVerifier to cover both constructors.
	cv := NewClientVerifier(
		WithTrustedTLHost("tl2.example"),
		WithOfflineMode(true),
		WithParallelFetch(true),
	)
	if cv == nil {
		t.Fatal("NewClientVerifier returned nil with combined options")
	}
}
