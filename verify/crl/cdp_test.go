package crl

import (
	"crypto/x509"
	"testing"
)

func TestResolveCDP_EmptyChain(t *testing.T) {
	result := ResolveCDP(nil)
	if result.Status != CDPSkipped {
		t.Errorf("got status %v, want CDPSkipped", result.Status)
	}
	if result.Message != "empty certificate chain" {
		t.Errorf("got message %q, want %q", result.Message, "empty certificate chain")
	}
}

func TestResolveCDP_NoCDPExtension(t *testing.T) {
	cert := &x509.Certificate{
		CRLDistributionPoints: nil,
	}
	result := ResolveCDP([]*x509.Certificate{cert})
	if result.Status != CDPSkipped {
		t.Errorf("got status %v, want CDPSkipped", result.Status)
	}
	if result.Message != "no CDP extension in certificate chain" {
		t.Errorf("got message %q", result.Message)
	}
}

func TestResolveCDP_HTTPURIFound(t *testing.T) {
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{
			"http://crl.example.com/root.crl",
		},
	}
	result := ResolveCDP([]*x509.Certificate{cert})
	if result.Status != CDPFound {
		t.Errorf("got status %v, want CDPFound", result.Status)
	}
	if result.URI != "http://crl.example.com/root.crl" {
		t.Errorf("got URI %q", result.URI)
	}
}

func TestResolveCDP_HTTPSURIFound(t *testing.T) {
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{
			"https://crl.example.com/root.crl",
		},
	}
	result := ResolveCDP([]*x509.Certificate{cert})
	if result.Status != CDPFound {
		t.Errorf("got status %v, want CDPFound", result.Status)
	}
	if result.URI != "https://crl.example.com/root.crl" {
		t.Errorf("got URI %q", result.URI)
	}
}

func TestResolveCDP_NonHTTPURI(t *testing.T) {
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{
			"ldap://directory.example.com/cn=Root",
		},
	}
	result := ResolveCDP([]*x509.Certificate{cert})
	if result.Status != CDPFailed {
		t.Errorf("got status %v, want CDPFailed", result.Status)
	}
	if result.Message != "CDP present but no HTTP(S) URI found" {
		t.Errorf("got message %q", result.Message)
	}
}

func TestResolveCDP_MixedURIs_FirstHTTPWins(t *testing.T) {
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{
			"ldap://directory.example.com/cn=Root",
			"http://crl.example.com/root.crl",
		},
	}
	result := ResolveCDP([]*x509.Certificate{cert})
	if result.Status != CDPFound {
		t.Errorf("got status %v, want CDPFound", result.Status)
	}
	if result.URI != "http://crl.example.com/root.crl" {
		t.Errorf("got URI %q", result.URI)
	}
}

func TestResolveCDP_WalksChain(t *testing.T) {
	leaf := &x509.Certificate{
		CRLDistributionPoints: nil,
	}
	intermediate := &x509.Certificate{
		CRLDistributionPoints: []string{
			"http://crl.intermediate.example.com/intermediate.crl",
		},
	}
	result := ResolveCDP([]*x509.Certificate{leaf, intermediate})
	if result.Status != CDPFound {
		t.Errorf("got status %v, want CDPFound", result.Status)
	}
	if result.URI != "http://crl.intermediate.example.com/intermediate.crl" {
		t.Errorf("got URI %q", result.URI)
	}
}

func TestIsHTTPURI(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"HTTP://example.com", false},
		{"ldap://example.com", false},
		{"ftp://example.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isHTTPURI(tt.uri); got != tt.want {
			t.Errorf("isHTTPURI(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}

func TestCDPStatus_Values(t *testing.T) {
	if CDPSkipped != 0 {
		t.Error("CDPSkipped should be 0")
	}
	if CDPFound != 1 {
		t.Error("CDPFound should be 1")
	}
	if CDPFailed != 2 {
		t.Error("CDPFailed should be 2")
	}
}
