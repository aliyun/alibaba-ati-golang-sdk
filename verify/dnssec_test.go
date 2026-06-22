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
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(10 * time.Second)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 30*time.Second, nil)

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

// mockDNSServer starts a UDP DNS server with a custom handler and returns its address.
func mockDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	return pc.LocalAddr().String()
}

func TestDNSSECValidator_ValidateZoneChain_NoDNSKEYs(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	rrsig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG}, SignerName: "example.com.", KeyTag: 12345}

	valid, err := v.validateZoneChain(context.Background(), "example.com.", []dns.RR{rr}, rrsig)
	if err != nil {
		t.Logf("expected insecure delegation, got error: %v", err)
	}
	if valid {
		t.Error("expected false for zone with no DNSKEYs")
	}
}

func TestDNSSECValidator_ValidateZoneChain_KeyTagMismatch(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
				Flags:     256,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "AQPB+Id...",
			}
			m.Answer = append(m.Answer, key)
		}
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	rrsig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG}, SignerName: "example.com.", KeyTag: 65535}

	valid, err := v.validateZoneChain(context.Background(), "example.com.", []dns.RR{rr}, rrsig)
	if err == nil {
		t.Error("expected error for key tag mismatch")
	}
	if valid {
		t.Error("expected false for key tag mismatch")
	}
}

func TestDNSSECValidator_FetchDNSKEYs_CacheHit(t *testing.T) {
	v := newDNSSECValidator("192.0.2.1:53", 2*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "cached.com.", Rrtype: dns.TypeDNSKEY, Ttl: 300}, Flags: 256, Protocol: 3, Algorithm: 8},
	}
	v.cache.Store("cached.com.", &dnssecCacheEntry{
		keys:    keys,
		expires: time.Now().Add(1 * time.Hour),
	})

	got, err := v.fetchDNSKEYs(context.Background(), "cached.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 key from cache, got %d", len(got))
	}
}

func TestDNSSECValidator_FetchDNSKEYs_WithTTLCaching(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			m.Answer = append(m.Answer, &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     256,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "dGVzdA==",
			})
		}
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	keys, err := v.fetchDNSKEYs(context.Background(), "test.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Verify it was cached
	entry, ok := v.cache.Load("test.com.")
	if !ok {
		t.Fatal("expected cache entry")
	}
	ce := entry.(*dnssecCacheEntry)
	if len(ce.keys) != 1 {
		t.Errorf("cache has %d keys, want 1", len(ce.keys))
	}
}

func TestDNSSECValidator_ValidateDNSKEYSet_NoRRSIG(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			m.Answer = append(m.Answer, &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "dGVzdA==",
			})
		}
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeDNSKEY, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "dGVzdA=="},
	}

	err := v.validateDNSKEYSet(context.Background(), "test.com.", keys)
	if err == nil {
		t.Error("expected error when no RRSIG for DNSKEY")
	}
}

func TestDNSSECValidator_ValidateDSChain_NoDS(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "dGVzdA=="},
	}

	valid, err := v.validateDSChain(context.Background(), "example.com.", keys)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false for insecure delegation (no DS)")
	}
}

func TestDNSSECValidator_ValidateDSChain_DSMismatch(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDS {
			m.Answer = append(m.Answer, &dns.DS{
				Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
				KeyTag:     65535,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "0000000000000000000000000000000000000000000000000000000000000000",
			})
		}
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "dGVzdA=="},
	}

	valid, err := v.validateDSChain(context.Background(), "example.com.", keys)
	if err == nil {
		t.Error("expected error for DS mismatch")
	}
	if valid {
		t.Error("expected false for DS mismatch")
	}
}

func TestDNSSECValidator_ValidateRRset_NonEmpty(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	rr := &dns.A{Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	rrsig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeRRSIG}, SignerName: "test.com.", KeyTag: 12345}

	valid, _ := v.validateRRset(context.Background(), []dns.RR{rr}, []*dns.RRSIG{rrsig})
	if valid {
		t.Error("expected false when zone has no DNSKEYs")
	}
}

func TestDNSSECValidator_Exchange_QueryError(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// Don't respond to simulate timeout
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 200*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeDNSKEY)

	_, err := v.exchange(ctx, msg)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestDNSSECValidator_FetchDNSKEYs_QueryError(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// Don't respond to simulate timeout
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 200*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := v.fetchDNSKEYs(ctx, "unreachable.com.")
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestDNSSECValidator_ValidateDNSKEYSet_QueryError(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// Don't respond to simulate timeout
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 200*time.Millisecond, nil)

	keys := []*dns.DNSKEY{{Hdr: dns.RR_Header{Name: "test.com."}, Flags: 257}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := v.validateDNSKEYSet(ctx, "test.com.", keys)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestDNSSECValidator_ValidateDSChain_QueryError(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// Don't respond to simulate timeout
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 200*time.Millisecond, nil)

	keys := []*dns.DNSKEY{{Hdr: dns.RR_Header{Name: "test.com."}, Flags: 257}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := v.validateDSChain(ctx, "test.com.", keys)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestDNSSECValidator_ValidateDNSKEYSet_SigVerificationFailed(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "dGVzdA==",
			}
			rrsig := &dns.RRSIG{
				Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: dns.TypeDNSKEY,
				Algorithm:   dns.RSASHA256,
				SignerName:  r.Question[0].Name,
				KeyTag:      key.KeyTag(),
				Signature:   "invalidsig==",
			}
			m.Answer = append(m.Answer, key, rrsig)
		}
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeDNSKEY, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "dGVzdA=="},
	}

	err := v.validateDNSKEYSet(context.Background(), "test.com.", keys)
	if err == nil {
		t.Error("expected error for signature verification failure")
	}
}

func TestDNSSECValidator_ValidateDSChain_DSWithNoRRSIG(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDS {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "dGVzdA==",
			}
			computed := key.ToDS(2)
			if computed != nil {
				m.Answer = append(m.Answer, computed)
			}
		}
		_ = w.WriteMsg(m)
	})
	addr := mockDNSServer(t, handler)
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "dGVzdA=="},
	}

	valid, err := v.validateDSChain(context.Background(), "example.com.", keys)
	if err == nil {
		t.Error("expected error for DS without RRSIG")
	}
	if valid {
		t.Error("expected false for DS without RRSIG")
	}
}

func TestDNSSECValidator_VerifyRootKeys_KSKMatchesTrustAnchor(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}

	anchor := key.ToDS(2)
	if anchor == nil {
		t.Fatal("failed to compute DS for test key")
	}

	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, anchor)

	valid, err := v.verifyRootKeys([]*dns.DNSKEY{key})
	if err != nil {
		t.Fatalf("verifyRootKeys() error = %v", err)
	}
	if !valid {
		t.Error("expected true when KSK matches trust anchor")
	}
}

func TestDNSSECValidator_VerifyRootKeys_ZSKOnly(t *testing.T) {
	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, nil)

	keys := []*dns.DNSKEY{
		{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 256, Protocol: 3, Algorithm: 8, PublicKey: "dGVzdA=="},
	}

	valid, err := v.verifyRootKeys(keys)
	if valid {
		t.Error("expected false with only ZSK")
	}
	if err == nil {
		t.Error("expected error with only ZSK")
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
