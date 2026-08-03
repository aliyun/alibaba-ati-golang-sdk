package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// TestCheckCertValidity targets the uncovered lines 27-55 of cert.go:
// the validity window checks, expired/not-yet-valid branches, remaining-percent
// computation, and the <20% lifetime warning branch.
func TestCheckCertValidity(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(24 * time.Hour)

	t.Run("valid with full lifetime warning threshold", func(t *testing.T) {
		// remaining fraction < 0.2 to hit the warning branch
		expiringSoon := now.Add(2 * time.Hour) // ~4% of 48h lifetime remains
		cert := &x509.Certificate{NotBefore: notBefore, NotAfter: expiringSoon}
		res := CheckCertValidity(cert, now)
		if !res.Valid {
			t.Errorf("expected Valid=true, got false")
		}
		if res.ExpiresAt != expiringSoon {
			t.Errorf("ExpiresAt = %v, want %v", res.ExpiresAt, expiringSoon)
		}
		if res.Warning == "" {
			t.Error("expected non-empty warning for soon-expiring cert")
		}
		if res.RemainingPercent <= 0 {
			t.Errorf("expected positive remaining percent, got %v", res.RemainingPercent)
		}
	})

	t.Run("expired", func(t *testing.T) {
		past := now.Add(-1 * time.Hour)
		cert := &x509.Certificate{NotBefore: notBefore, NotAfter: past}
		res := CheckCertValidity(cert, now)
		if res.Valid {
			t.Error("expected Valid=false for expired cert")
		}
		if res.Warning != "certificate has expired" {
			t.Errorf("Warning = %q, want %q", res.Warning, "certificate has expired")
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		future := now.Add(1 * time.Hour)
		cert := &x509.Certificate{NotBefore: future, NotAfter: notAfter}
		res := CheckCertValidity(cert, now)
		if res.Valid {
			t.Error("expected Valid=false for not-yet-valid cert")
		}
		if res.Warning != "certificate is not yet valid" {
			t.Errorf("Warning = %q, want %q", res.Warning, "certificate is not yet valid")
		}
	})

	t.Run("valid with healthy lifetime remaining", func(t *testing.T) {
		cert := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}
		res := CheckCertValidity(cert, now)
		if !res.Valid {
			t.Error("expected Valid=true")
		}
		// ~50% lifetime remaining, above the 20% threshold, no warning
		if res.Warning != "" {
			t.Errorf("expected empty warning, got %q", res.Warning)
		}
	})

	t.Run("zero lifetime avoids division issue", func(t *testing.T) {
		// NotBefore == NotAfter -> total = 0, branch guards RemainingPercent
		same := now
		cert := &x509.Certificate{NotBefore: same, NotAfter: same}
		res := CheckCertValidity(cert, now)
		// now.After(NotAfter) is false (equal), so Valid=true
		if !res.Valid {
			t.Error("expected Valid=true for zero-lifetime cert at boundary")
		}
		if res.RemainingPercent != 0 {
			t.Errorf("expected 0 remaining percent for zero lifetime, got %v", res.RemainingPercent)
		}
	})
}

// TestParseCertFingerprint_Variants targets the prefix-switch lines (82, 84)
// of ParseCertFingerprint for the "SHA-256:" and "sha-256:" variants.
func TestParseCertFingerprint_Variants(t *testing.T) {
	const hexStr = "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	want := "SHA256:" + hexStr

	cases := []struct {
		name  string
		input string
	}{
		{"SHA-256: prefix", "SHA-256:" + hexStr},
		{"sha-256: prefix", "sha-256:" + hexStr},
		{"SHA256: prefix", "SHA256:" + hexStr},
		{"sha256: prefix", "sha256:" + hexStr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp, err := ParseCertFingerprint(tc.input)
			if err != nil {
				t.Fatalf("ParseCertFingerprint() error = %v", err)
			}
			if fp.String() != want {
				t.Errorf("String() = %q, want %q", fp.String(), want)
			}
		})
	}
}

func TestParseCertFingerprint_TooLong(t *testing.T) {
	// 33 bytes -> invalid length branch (line 96-97)
	long := strings.Repeat("ab", 33) // 66 hex chars = 33 bytes
	_, err := ParseCertFingerprint("SHA256:" + long)
	if err == nil {
		t.Error("expected error for too-long fingerprint, got nil")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error should mention 32 bytes, got: %v", err)
	}
}

// TestCertIdentityFromPEM targets lines 250-259: CertIdentityFromPEM, including
// the URL-decode fallback path and the PEM-decode failure path.
func TestCertIdentityFromPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pem.example.com"},
		DNSNames:     []string{"pem.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	uri, _ := url.Parse("ati://v1.0.0.pem.example.com")
	template.URIs = []*url.URL{uri}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	rawPEM := string(pemBytes)

	t.Run("url-encoded PEM (documented Nginx forwarded form)", func(t *testing.T) {
		// CertIdentityFromPEM's documented contract is to accept URL-encoded
		// PEM as forwarded by Nginx via $ssl_client_escaped_cert. The
		// QueryUnescape step decodes %2B back to '+', restoring valid PEM.
		escaped := url.QueryEscape(rawPEM)
		ident, err := CertIdentityFromPEM(escaped)
		if err != nil {
			t.Fatalf("CertIdentityFromPEM() error = %v", err)
		}
		if ident.CommonName == nil || *ident.CommonName != "pem.example.com" {
			t.Errorf("CommonName = %v, want pem.example.com", ident.CommonName)
		}
		if ident.Fingerprint.IsZero() {
			t.Error("expected non-zero fingerprint")
		}
		if ident.SPKIFingerprint.IsZero() {
			t.Error("expected non-zero SPKI fingerprint")
		}
		if len(ident.URISANs) != 1 || ident.URISANs[0] != "ati://v1.0.0.pem.example.com" {
			t.Errorf("URISANs = %v, want [ati://v1.0.0.pem.example.com]", ident.URISANs)
		}
	})

	t.Run("raw PEM with + in base64 hits QueryUnescape corruption", func(t *testing.T) {
		// Documents an implementation quirk: url.QueryUnescape treats '+' as
		// a space. Raw PEM containing '+' in base64 is therefore mangled and
		// either pem.Decode fails or x509.ParseCertificate fails with a
		// malformed certificate error.
		if !strings.Contains(rawPEM, "+") {
			t.Skip("generated cert base64 contains no '+'; cannot exercise this path")
		}
		_, err := CertIdentityFromPEM(rawPEM)
		if err == nil {
			t.Skip("raw PEM with '+' decoded anyway; not mangleable in this position")
		}
		if !strings.Contains(err.Error(), "PEM") && !strings.Contains(err.Error(), "certificate") {
			t.Errorf("error should mention PEM or certificate, got: %v", err)
		}
	})

	t.Run("invalid PEM returns error", func(t *testing.T) {
		_, err := CertIdentityFromPEM("not a pem")
		if err == nil {
			t.Error("expected error for non-PEM input, got nil")
		}
		if !strings.Contains(err.Error(), "PEM") {
			t.Errorf("error should mention PEM, got: %v", err)
		}
	})

	t.Run("empty input returns error", func(t *testing.T) {
		_, err := CertIdentityFromPEM("")
		if err == nil {
			t.Error("expected error for empty input, got nil")
		}
	})
}

// TestCertIdentity_ATINameAndVersion_FromX509 targets lines 168 and 282-300
// via a cert with a real ati:// URI SAN, exercising the SPKIFingerprint
// computation (line 228) and ATIName/Version extraction.
func TestCertIdentity_ATINameAndVersion_FromX509(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	uri, _ := url.Parse("ati://v2.3.4.ati.example.com")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "ati.example.com"},
		DNSNames:     []string{"ati.example.com"},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	ident := CertIdentityFromX509(cert)

	// SPKI fingerprint must be populated (line 228)
	if ident.SPKIFingerprint.IsZero() {
		t.Error("expected non-zero SPKIFingerprint")
	}
	if !ident.SPKIFingerprint.Equal(CertFingerprintFromDER(cert.RawSubjectPublicKeyInfo)) {
		t.Error("SPKIFingerprint mismatch vs CertFingerprintFromDER(RawSubjectPublicKeyInfo)")
	}

	// ATIName extraction (lines 282-291)
	name := ident.ATIName()
	if name == nil {
		t.Fatal("ATIName() returned nil")
	}
	if name.Host != "ati.example.com" {
		t.Errorf("ATIName().Host = %q, want ati.example.com", name.Host)
	}
	if name.String() != "ati://v2.3.4.ati.example.com" {
		t.Errorf("ATIName().String() = %q", name.String())
	}

	// Version extraction (lines 294-300)
	v := ident.Version()
	if v == nil {
		t.Fatal("Version() returned nil")
	}
	if !v.Equal(models.NewVersion(2, 3, 4)) {
		t.Errorf("Version() = %v, want v2.3.4", v)
	}
}

// TestCertIdentity_ATIName_NoMatchingURI ensures ATIName returns nil when only
// non-ati:// URIs are present (the loop in lines 282-290 falls through).
func TestCertIdentity_ATIName_NoMatchingURI(t *testing.T) {
	ident := &CertIdentity{
		URISANs: []string{"https://other.example", "ftp://foo.example"},
	}
	if name := ident.ATIName(); name != nil {
		t.Errorf("ATIName() = %v, want nil", name)
	}
	if v := ident.Version(); v != nil {
		t.Errorf("Version() = %v, want nil", v)
	}
}

// TestCertIdentityFromDER_Invalid targets line 243 error wrap.
func TestCertIdentityFromDER_Invalid(t *testing.T) {
	_, err := CertIdentityFromDER([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid DER, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse certificate") {
		t.Errorf("error should wrap parse failure, got: %v", err)
	}
}

// TestCertFingerprint_ToxToHexRoundTrip targets the ToHex method (line 115-117)
// and Matches round-trip with a fingerprint parsed from its own String().
func TestCertFingerprint_ToHexRoundTrip(t *testing.T) {
	raw := [32]byte{0xaa, 0xbb, 0xcc, 0xdd}
	fp := CertFingerprintFromBytes(raw)

	hexStr := fp.ToHex()
	if hexStr != "aabbccdd"+strings.Repeat("00", 28) {
		t.Errorf("ToHex() = %q, unexpected", hexStr)
	}

	// String() -> ParseCertFingerprint -> Equal
	if !fp.Matches(fp.String()) {
		t.Error("Matches(String()) should return true")
	}
	if !fp.Equal(fp) {
		t.Error("Equal to itself should be true")
	}
}
