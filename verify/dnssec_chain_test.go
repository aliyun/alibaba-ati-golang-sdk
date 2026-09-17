package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnssecTestZone holds test DNSSEC key material for a zone.
type dnssecTestZone struct {
	ksk     *dns.DNSKEY
	kskPriv crypto.PrivateKey
	zsk     *dns.DNSKEY
	zskPriv crypto.PrivateKey
	zone    string
}

func generateDNSSECZone(t *testing.T, zone string) *dnssecTestZone {
	t.Helper()

	// Generate KSK (flags=257)
	ksk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	kskPriv, err := ksk.Generate(256)
	if err != nil {
		t.Fatalf("failed to generate KSK for %s: %v", zone, err)
	}

	// Generate ZSK (flags=256)
	zsk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	zskPriv, err := zsk.Generate(256)
	if err != nil {
		t.Fatalf("failed to generate ZSK for %s: %v", zone, err)
	}

	return &dnssecTestZone{
		ksk:     ksk,
		kskPriv: kskPriv,
		zsk:     zsk,
		zskPriv: zskPriv,
		zone:    zone,
	}
}

// signRRset creates an RRSIG signing the given RRset with the specified key.
func signRRset(t *testing.T, rrset []dns.RR, key *dns.DNSKEY, priv crypto.PrivateKey, zone string) *dns.RRSIG {
	t.Helper()
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		Algorithm:  key.Algorithm,
		SignerName: zone,
		KeyTag:    key.KeyTag(),
		Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()),
	}
	if err := rrsig.Sign(priv.(*ecdsa.PrivateKey), rrset); err != nil {
		t.Fatalf("failed to sign RRset: %v", err)
	}
	return rrsig
}

// startDNSSECFakeServer starts a DNS server serving full DNSSEC chain records.
// Returns the server address and the root trust anchor DS.
func startDNSSECFakeServer(t *testing.T) (string, *dns.DS) {
	t.Helper()

	// Generate zones: root (.), com., example.com.
	rootZone := generateDNSSECZone(t, ".")
	comZone := generateDNSSECZone(t, "com.")
	exampleZone := generateDNSSECZone(t, "example.com.")

	// Build DS records (child KSK → parent DS)
	comDS := comZone.ksk.ToDS(dns.SHA256)
	comDS.Hdr = dns.RR_Header{Name: "com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}

	exampleDS := exampleZone.ksk.ToDS(dns.SHA256)
	exampleDS.Hdr = dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}

	// Trust anchor = root KSK DS
	rootDS := rootZone.ksk.ToDS(dns.SHA256)
	rootDS.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET}

	// Create a TXT record signed by example.com ZSK
	txtRR := &dns.TXT{
		Hdr: dns.RR_Header{Name: "_ati-badge.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=ati-badge1; version=v1.0.0; url=https://tlog.example.com/badge/1"},
	}

	// Sign TXT with example.com ZSK
	txtRRSIG := signRRset(t, []dns.RR{txtRR}, exampleZone.zsk, exampleZone.zskPriv, "example.com.")

	// Sign DNSKEY sets with their own KSKs
	rootDNSKEYs := []dns.RR{rootZone.ksk, rootZone.zsk}
	rootDNSKEYRRSIG := signRRset(t, rootDNSKEYs, rootZone.ksk, rootZone.kskPriv, ".")

	comDNSKEYs := []dns.RR{comZone.ksk, comZone.zsk}
	comDNSKEYRRSIG := signRRset(t, comDNSKEYs, comZone.ksk, comZone.kskPriv, "com.")

	exDNSKEYs := []dns.RR{exampleZone.ksk, exampleZone.zsk}
	exDNSKEYRRSIG := signRRset(t, exDNSKEYs, exampleZone.ksk, exampleZone.kskPriv, "example.com.")

	// Sign DS records with parent ZSK
	comDSRRSIG := signRRset(t, []dns.RR{comDS}, rootZone.zsk, rootZone.zskPriv, ".")
	exDSRRSIG := signRRset(t, []dns.RR{exampleDS}, comZone.zsk, comZone.zskPriv, "com.")

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			switch {
			case q.Qtype == dns.TypeDNSKEY && q.Name == ".":
				m.Answer = append(m.Answer, rootZone.ksk, rootZone.zsk, rootDNSKEYRRSIG)
			case q.Qtype == dns.TypeDNSKEY && q.Name == "com.":
				m.Answer = append(m.Answer, comZone.ksk, comZone.zsk, comDNSKEYRRSIG)
			case q.Qtype == dns.TypeDNSKEY && q.Name == "example.com.":
				m.Answer = append(m.Answer, exampleZone.ksk, exampleZone.zsk, exDNSKEYRRSIG)
			case q.Qtype == dns.TypeDS && q.Name == "com.":
				m.Answer = append(m.Answer, comDS, comDSRRSIG)
			case q.Qtype == dns.TypeDS && q.Name == "example.com.":
				m.Answer = append(m.Answer, exampleDS, exDSRRSIG)
			case q.Qtype == dns.TypeTXT && q.Name == "_ati-badge.example.com.":
				m.Answer = append(m.Answer, txtRR, txtRRSIG)
			default:
				m.Rcode = dns.RcodeNameError
			}
		}
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	return pc.LocalAddr().String(), rootDS
}

func TestDNSSECValidator_ValidateZoneChain_FullChain(t *testing.T) {
	addr, rootDS := startDNSSECFakeServer(t)

	v := newDNSSECValidator(addr, 5*time.Second, rootDS)

	// Fetch TXT and RRSIG from the server
	c := &dns.Client{Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion("_ati-badge.example.com.", dns.TypeTXT)
	msg.SetEdns0(4096, true)

	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("DNS query failed: %v", err)
	}

	var rrset []dns.RR
	var rrsigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.TXT:
			rrset = append(rrset, rr)
		case *dns.RRSIG:
			rrsigs = append(rrsigs, r)
		}
	}

	if len(rrset) == 0 || len(rrsigs) == 0 {
		t.Fatal("no TXT or RRSIG records returned")
	}

	valid, err := v.validateRRset(context.Background(), rrset, rrsigs)
	if err != nil {
		t.Fatalf("validateRRset() error = %v", err)
	}
	if !valid {
		t.Error("validateRRset() = false, want true for full DNSSEC chain")
	}
}

func TestDNSSECValidator_ValidateZoneChain_InsecureDelegation(t *testing.T) {
	// DNS server that returns empty DNSKEY for a zone = insecure delegation
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		// Return no DNSKEY records for any zone = insecure
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	// Create a dummy RRSIG pointing to example.com.
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		Algorithm:  dns.ECDSAP256SHA256,
		SignerName: "example.com.",
		KeyTag:    12345,
	}
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"test"},
	}

	valid, err := v.validateRRset(context.Background(), []dns.RR{rr}, []*dns.RRSIG{rrsig})
	if err != nil {
		t.Fatalf("validateRRset() error = %v", err)
	}
	if valid {
		t.Error("validateRRset() = true, want false for insecure delegation (no DNSKEY)")
	}
}

func TestDNSSECValidator_ValidateZoneChain_KeyTagMismatch(t *testing.T) {
	// Server returns DNSKEY but with different key tag than the RRSIG
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	key.Generate(256) //nolint:errcheck

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			m.Answer = append(m.Answer, key)
		}
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		Algorithm:  dns.ECDSAP256SHA256,
		SignerName: "example.com.",
		KeyTag:    65534, // doesn't match any key
	}
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"test"},
	}

	_, err = v.validateRRset(context.Background(), []dns.RR{rr}, []*dns.RRSIG{rrsig})
	if err == nil {
		t.Fatal("expected error for key tag mismatch")
	}
}

func TestDNSSECValidator_FetchDNSKEYs_CacheHit(t *testing.T) {
	// Pre-populate cache; the server should never be contacted
	v := newDNSSECValidator("192.0.2.1:53", 100*time.Millisecond, nil)

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "cached.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	v.cache.Store("cached.com.", &dnssecCacheEntry{
		keys:    []*dns.DNSKEY{key},
		expires: time.Now().Add(1 * time.Hour),
	})

	keys, err := v.fetchDNSKEYs(context.Background(), "cached.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYs() error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 cached key, got %d", len(keys))
	}
}

func TestDNSSECValidator_ValidateDNSKEYSet_NoRRSIG(t *testing.T) {
	// Server returns DNSKEY but no RRSIG for DNSKEY
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	key.Generate(256) //nolint:errcheck

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			m.Answer = append(m.Answer, key) // no RRSIG
		}
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	err = v.validateDNSKEYSet(context.Background(), "example.com.", []*dns.DNSKEY{key})
	if err == nil {
		t.Fatal("expected error when no RRSIG for DNSKEY")
	}
}

func TestDNSSECValidator_ValidateDSChain_NoDSRecords(t *testing.T) {
	// Server returns no DS records = insecure delegation
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		// Return nothing for DS queries
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	// Generate a KSK for the zone
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	key.Generate(256) //nolint:errcheck

	valid, err := v.validateDSChain(context.Background(), "example.com.", []*dns.DNSKEY{key})
	if err != nil {
		t.Fatalf("validateDSChain() error: %v", err)
	}
	if valid {
		t.Error("validateDSChain() = true, want false for no DS records (insecure delegation)")
	}
}

func TestDNSSECValidator_ValidateDSChain_DSMismatch(t *testing.T) {
	// Server returns a DS record that doesn't match any KSK
	fakeDS := &dns.DS{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
		KeyTag:     65534,
		Algorithm:  dns.ECDSAP256SHA256,
		DigestType: dns.SHA256,
		Digest:     "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeDS {
			m.Answer = append(m.Answer, fakeDS)
		}
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()
	v := newDNSSECValidator(addr, 2*time.Second, nil)

	// Generate a KSK
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	key.Generate(256) //nolint:errcheck

	_, err = v.validateDSChain(context.Background(), "example.com.", []*dns.DNSKEY{key})
	if err == nil {
		t.Fatal("expected error when DS doesn't match any KSK")
	}
}

func TestDNSSECValidator_VerifyRootKeys_Match(t *testing.T) {
	// Generate root keys
	rootKey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	_, err := rootKey.Generate(256)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	// Compute the DS from the KSK (this is what we'd use as trust anchor)
	ds := rootKey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET}

	v := newDNSSECValidator("8.8.8.8:53", 5*time.Second, ds)

	valid, err := v.verifyRootKeys([]*dns.DNSKEY{rootKey})
	if err != nil {
		t.Fatalf("verifyRootKeys() error: %v", err)
	}
	if !valid {
		t.Error("verifyRootKeys() = false, want true when KSK matches trust anchor")
	}
}

func TestDNSSECValidator_ParentOf_AdditionalCases(t *testing.T) {
	tests := []struct {
		zone string
		want string
	}{
		{"deep.sub.example.com.", "sub.example.com."},
		{"a.", "."},
		{"", "."},
	}
	for _, tt := range tests {
		got := parentOf(tt.zone)
		if got != tt.want {
			t.Errorf("parentOf(%q) = %q, want %q", tt.zone, got, tt.want)
		}
	}
}

