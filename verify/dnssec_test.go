package verify

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParentOf(t *testing.T) {
	tests := []struct {
		zone string
		want string
	}{
		{"example.com.", "com."},
		{"com.", "."},
		{".", "."},
		{"sub.example.com.", "example.com."},
		{"a.b.c.d.", "b.c.d."},
		{"example.com", "com."},  // without trailing dot
		{"single.", "."},         // single label
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			got := parentOf(tt.zone)
			if got != tt.want {
				t.Errorf("parentOf(%q) = %q, want %q", tt.zone, got, tt.want)
			}
		})
	}
}

func TestNewDNSSECValidator_DefaultTrustAnchor(t *testing.T) {
	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, nil)
	if v.trustAnchor == nil {
		t.Fatal("expected default trust anchor to be set")
	}
	if v.trustAnchor.KeyTag != 20326 {
		t.Errorf("trust anchor key tag = %d, want 20326", v.trustAnchor.KeyTag)
	}
	if v.server != "8.8.8.8:53" {
		t.Errorf("server = %q, want %q", v.server, "8.8.8.8:53")
	}
}

func TestNewDNSSECValidator_CustomTrustAnchor(t *testing.T) {
	custom := &dns.DS{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     12345,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "abcdef",
	}
	v := newDNSSECValidator("1.1.1.1:53", 10*time.Second, custom)
	if v.trustAnchor.KeyTag != 12345 {
		t.Errorf("trust anchor key tag = %d, want 12345", v.trustAnchor.KeyTag)
	}
	if v.server != "1.1.1.1:53" {
		t.Errorf("server = %q, want %q", v.server, "1.1.1.1:53")
	}
}

func TestDNSSECValidator_ValidateRRset_EmptyInputs(t *testing.T) {
	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, nil)

	t.Run("nil rrset", func(t *testing.T) {
		valid, err := v.validateRRset(context.Background(), nil, []*dns.RRSIG{{}})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if valid {
			t.Error("expected false for nil rrset")
		}
	})

	t.Run("nil rrsigs", func(t *testing.T) {
		rr := &dns.TLSA{Hdr: dns.RR_Header{Name: "_443._tcp.example.com.", Rrtype: dns.TypeTLSA}}
		valid, err := v.validateRRset(context.Background(), []dns.RR{rr}, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if valid {
			t.Error("expected false for nil rrsigs")
		}
	})

	t.Run("empty rrset", func(t *testing.T) {
		valid, err := v.validateRRset(context.Background(), []dns.RR{}, []*dns.RRSIG{{}})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if valid {
			t.Error("expected false for empty rrset")
		}
	})
}

func TestDNSSECValidator_Cache(t *testing.T) {
	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, nil)

	// Store a cache entry
	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY}, Flags: 256},
	}
	v.cache.Store("example.com.", &dnssecCacheEntry{
		keys:    keys,
		expires: time.Now().Add(1 * time.Hour),
	})

	// Verify cache hit
	if entry, ok := v.cache.Load("example.com."); ok {
		ce := entry.(*dnssecCacheEntry)
		if len(ce.keys) != 1 {
			t.Errorf("cache has %d keys, want 1", len(ce.keys))
		}
		if time.Now().After(ce.expires) {
			t.Error("cache entry should not be expired")
		}
	} else {
		t.Error("expected cache entry for example.com.")
	}

	// Verify cache miss
	if _, ok := v.cache.Load("notcached.com."); ok {
		t.Error("should not have cache entry for notcached.com.")
	}
}

func TestDNSSECValidator_CacheExpiry(t *testing.T) {
	// Use unreachable address with very short timeout to ensure failure
	v := newDNSSECValidator("192.0.2.1:53", 100*time.Millisecond, nil)

	// Store an expired cache entry
	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "expired.com.", Rrtype: dns.TypeDNSKEY}, Flags: 256},
	}
	v.cache.Store("expired.com.", &dnssecCacheEntry{
		keys:    keys,
		expires: time.Now().Add(-1 * time.Hour), // already expired
	})

	// fetchDNSKEYs should detect expiry and try to query (which will fail since server is unreachable)
	_, err := v.fetchDNSKEYs(context.Background(), "expired.com.")
	if err == nil {
		t.Error("expected error when fetching expired cache entry with unreachable server")
	}
}

func TestDNSSECValidator_VerifyRootKeys(t *testing.T) {
	// Create a validator with a known trust anchor
	anchor := &dns.DS{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
	}
	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, anchor)

	t.Run("no matching KSK", func(t *testing.T) {
		// ZSK only (flags=256), no KSK
		keys := []*dns.DNSKEY{
			{
				Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
				Flags:     256,
				Protocol:  3,
				Algorithm: 8,
				PublicKey: "dGVzdA==",
			},
		}
		valid, err := v.verifyRootKeys(keys)
		if valid {
			t.Error("expected false when no KSK matches")
		}
		if err == nil {
			t.Error("expected error when no KSK matches")
		}
	})
}

func TestDNSSECValidator_Exchange_TCPFallback(t *testing.T) {
	// Start a mock DNS server that returns truncated UDP response
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})

	tcpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		})
		_ = w.WriteMsg(m)
	})

	// Start UDP server
	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	udpServer := &dns.Server{PacketConn: udpPC, Handler: udpHandler}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = udpServer.ActivateAndServe()
	}()
	defer udpServer.Shutdown()

	udpAddr := udpPC.LocalAddr().String()

	// Start TCP server on same port
	_, port, _ := net.SplitHostPort(udpAddr)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: tcpHandler}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tcpServer.ActivateAndServe()
	}()
	defer tcpServer.Shutdown()

	// Give servers a moment to start
	time.Sleep(50 * time.Millisecond)

	v := newDNSSECValidator(udpAddr, 5*time.Second, nil)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resp, err := v.exchange(context.Background(), msg)
	if err != nil {
		t.Fatalf("exchange() failed: %v", err)
	}
	if resp.Truncated {
		t.Error("TCP fallback response should not be truncated")
	}
	if len(resp.Answer) == 0 {
		t.Error("expected answer in TCP fallback response")
	}
}

func TestDNSSECValidator_Exchange_ContextDeadline(t *testing.T) {
	v := newDNSSECValidator("192.0.2.1:53", 30*time.Second, nil) // unreachable IP

	// Use a very short context deadline
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	_, err := v.exchange(ctx, msg)
	if err == nil {
		t.Error("expected error with expired context")
	}
}

func TestWithDANETrustAnchor(t *testing.T) {
	custom := &dns.DS{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     54321,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "aabbccdd",
	}

	r := NewStandardDANEResolver(WithDANETrustAnchor(custom))
	if r.trustAnchor == nil {
		t.Fatal("trust anchor should be set")
	}
	if r.trustAnchor.KeyTag != 54321 {
		t.Errorf("trust anchor key tag = %d, want 54321", r.trustAnchor.KeyTag)
	}
	if r.validator == nil {
		t.Fatal("validator should be initialized")
	}
	if r.validator.trustAnchor.KeyTag != 54321 {
		t.Errorf("validator trust anchor key tag = %d, want 54321", r.validator.trustAnchor.KeyTag)
	}
}

func TestStandardDANEResolver_ValidatorInitialized(t *testing.T) {
	r := NewStandardDANEResolver()
	if r.validator == nil {
		t.Fatal("validator should be initialized")
	}
	if r.validator.server != "8.8.8.8:53" {
		t.Errorf("validator server = %q, want %q", r.validator.server, "8.8.8.8:53")
	}
	if r.validator.trustAnchor == nil {
		t.Error("validator trust anchor should default to IANA root anchor")
	}
}

func TestDNSSECValidator_CacheConcurrency(t *testing.T) {
	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			zone := "example.com."
			keys := []*dns.DNSKEY{
				{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY}, Flags: 256},
			}
			v.cache.Store(zone, &dnssecCacheEntry{
				keys:    keys,
				expires: time.Now().Add(1 * time.Hour),
			})
			v.cache.Load(zone)
		}(i)
	}
	wg.Wait()
}
