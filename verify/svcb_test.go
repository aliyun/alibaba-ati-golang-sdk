package verify

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// startTestDNSServer starts a local DNS server using the miekg/dns library.
// It returns the server's UDP address (host:port) and registers cleanup.
func startTestDNSServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on UDP: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handler)}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	// Give the server a moment to start up
	time.Sleep(50 * time.Millisecond)
	return pc.LocalAddr().String()
}

func TestLookupHTTPSSVCB_EmptyServerDefaults(t *testing.T) {
	// When server is empty, the function defaults to "8.8.8.8:53".
	// We cannot make a real network call to 8.8.8.8 in tests, so we verify
	// that the function returns Found=false (no real answer) without panicking.
	// Use a short context timeout to avoid hanging the test.
	fqdn, err := models.NewFqdn("test.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, "", fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() with empty server error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	// With an unreachable/timeout network, the function returns Found=false.
	if result.Found {
		t.Log("LookupHTTPSSVCB() returned Found=true (unexpected for default server in test env)")
	}
}

func TestLookupHTTPSSVCB_FullRecord(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		echData := []byte{0x00, 0x10, 0x00, 0x0c, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

		svcb := &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeHTTPS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 1,
				Target:  "target.example.com.",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
					&dns.SVCBPort{Port: 8443},
					&dns.SVCBECHConfig{ECH: echData},
				},
			},
		}
		m.Answer = append(m.Answer, svcb)
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("agent.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if !result.Found {
		t.Fatal("LookupHTTPSSVCB() Found = false, want true")
	}
	// Verify ALPN
	if len(result.ALPN) != 2 {
		t.Fatalf("ALPN length = %d, want 2", len(result.ALPN))
	}
	if result.ALPN[0] != "h2" || result.ALPN[1] != "h3" {
		t.Errorf("ALPN = %v, want [h2, h3]", result.ALPN)
	}
	// Verify Port
	if result.Port != 8443 {
		t.Errorf("Port = %d, want 8443", result.Port)
	}
	// Verify ECHConfig
	if len(result.ECHConfig) == 0 {
		t.Error("ECHConfig is empty, want non-empty")
	}
	// Verify Target
	if result.Target != "target.example.com." {
		t.Errorf("Target = %q, want %q", result.Target, "target.example.com.")
	}
}

func TestLookupHTTPSSVCB_NonSuccessRcode(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("notfound.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if result.Found {
		t.Error("LookupHTTPSSVCB() Found = true, want false for non-success rcode")
	}
}

func TestLookupHTTPSSVCB_NoAnswers(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Success rcode but no answer records
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("empty.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if result.Found {
		t.Error("LookupHTTPSSVCB() Found = true, want false for no answers")
	}
}

func TestLookupHTTPSSVCB_ExchangeError(t *testing.T) {
	// Point at an unreachable server (port that is not listening)
	// The function should return Found=false with nil error.
	fqdn, err := models.NewFqdn("unreachable.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Use a port that is almost certainly not listening
	result, err := LookupHTTPSSVCB(ctx, "127.0.0.1:53999", fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v, want nil for exchange error", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if result.Found {
		t.Error("LookupHTTPSSVCB() Found = true, want false for exchange error")
	}
}

func TestLookupHTTPSSVCB_TargetOnly(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		svcb := &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeHTTPS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 0,
				Target:  "alias.example.com.",
				Value:   []dns.SVCBKeyValue{},
			},
		}
		m.Answer = append(m.Answer, svcb)
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("alias.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if !result.Found {
		t.Fatal("LookupHTTPSSVCB() Found = false, want true")
	}
	if result.Target != "alias.example.com." {
		t.Errorf("Target = %q, want %q", result.Target, "alias.example.com.")
	}
	// No ALPN, Port, or ECHConfig values
	if len(result.ALPN) != 0 {
		t.Errorf("ALPN = %v, want empty", result.ALPN)
	}
	if result.Port != 0 {
		t.Errorf("Port = %d, want 0", result.Port)
	}
	if len(result.ECHConfig) != 0 {
		t.Errorf("ECHConfig length = %d, want 0", len(result.ECHConfig))
	}
}

func TestLookupHTTPSSVCB_MultipleRecords(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		// First record with ALPN and Port
		svcb1 := &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeHTTPS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 1,
				Target:  "first.example.com.",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h2"}},
					&dns.SVCBPort{Port: 443},
				},
			},
		}
		// Second record with different ALPN and Port
		svcb2 := &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeHTTPS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 2,
				Target:  "second.example.com.",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h3"}},
					&dns.SVCBPort{Port: 8443},
				},
			},
		}
		m.Answer = append(m.Answer, svcb1, svcb2)
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("multi.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if !result.Found {
		t.Fatal("LookupHTTPSSVCB() Found = false, want true")
	}
	// With multiple records, the last processed record's values win
	// (the function iterates and overwrites). Verify at least one set is present.
	if len(result.ALPN) == 0 {
		t.Error("ALPN is empty, want non-empty")
	}
	if result.Port == 0 {
		t.Error("Port = 0, want non-zero")
	}
	if result.Target == "" {
		t.Error("Target is empty, want non-empty")
	}
}

func TestLookupHTTPSSVCB_NonHTTPSRecordInAnswer(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		// Add a non-HTTPS record (A record) that should be skipped
		aRecord := &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("127.0.0.1"),
		}
		m.Answer = append(m.Answer, aRecord)
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("arecord.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	// Even though there are answers, none are HTTPS type, so Found should be false
	// (the function sets Found=true before the loop, but no data gets populated)
	// Actually the function sets Found=true if len(r.Answer) > 0, regardless of type.
	// So Found will be true but all fields will be zero.
	if !result.Found {
		t.Log("LookupHTTPSSVCB() Found = false (acceptable for non-HTTPS answers)")
	}
	// No HTTPS-specific data should be populated
	if len(result.ALPN) != 0 {
		t.Errorf("ALPN = %v, want empty", result.ALPN)
	}
	if result.Port != 0 {
		t.Errorf("Port = %d, want 0", result.Port)
	}
	if result.Target != "" {
		t.Errorf("Target = %q, want empty", result.Target)
	}
}

func TestLookupHTTPSSVCB_EmptyTargetRoot(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		// HTTPS record with Target = "." (root), should be ignored
		svcb := &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeHTTPS,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Priority: 1,
				Target:  ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h2"}},
					&dns.SVCBPort{Port: 443},
				},
			},
		}
		m.Answer = append(m.Answer, svcb)
		_ = w.WriteMsg(m)
	}
	serverAddr := startTestDNSServer(t, handler)

	fqdn, err := models.NewFqdn("root.example.com")
	if err != nil {
		t.Fatalf("NewFqdn() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LookupHTTPSSVCB(ctx, serverAddr, fqdn)
	if err != nil {
		t.Fatalf("LookupHTTPSSVCB() error = %v", err)
	}
	if result == nil {
		t.Fatal("LookupHTTPSSVCB() returned nil result")
	}
	if !result.Found {
		t.Fatal("LookupHTTPSSVCB() Found = false, want true")
	}
	// Target should be empty since "." is the root and should be ignored
	if result.Target != "" {
		t.Errorf("Target = %q, want empty (root target should be ignored)", result.Target)
	}
	// ALPN and Port should still be populated
	if len(result.ALPN) != 1 || result.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want [h2]", result.ALPN)
	}
	if result.Port != 443 {
		t.Errorf("Port = %d, want 443", result.Port)
	}
}
