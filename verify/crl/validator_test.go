package crl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CRL CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	return cert, key
}

func generateTestCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revokedSerials ...*big.Int) []byte {
	t.Helper()
	var revokedEntries []x509.RevocationListEntry
	for _, serial := range revokedSerials {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-1 * time.Hour),
		})
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: revokedEntries,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-1 * time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlBytes
}

func TestParse_ValidCRL(t *testing.T) {
	ca, caKey := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey)

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if rl == nil {
		t.Fatal("Parse() returned nil")
	}
}

func TestParse_InvalidData(t *testing.T) {
	_, err := Parse([]byte("not a valid CRL"))
	if err != ErrParseFailed {
		t.Errorf("Parse() error = %v, want ErrParseFailed", err)
	}
}

func TestVerifySignature_ValidSignature(t *testing.T) {
	ca, caKey := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey)

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if err := VerifySignature(rl, ca); err != nil {
		t.Errorf("VerifySignature() error = %v, want nil", err)
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	ca, caKey := generateTestCA(t)
	otherCA, _ := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey)

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if err := VerifySignature(rl, otherCA); err != ErrInvalidSignature {
		t.Errorf("VerifySignature() error = %v, want ErrInvalidSignature", err)
	}
}

func TestIsRevoked_SerialInCRL(t *testing.T) {
	ca, caKey := generateTestCA(t)
	revokedSerial := big.NewInt(12345)
	crlBytes := generateTestCRL(t, ca, caKey, revokedSerial)

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !IsRevoked(rl, revokedSerial) {
		t.Error("IsRevoked() = false, want true for revoked serial")
	}
}

func TestIsRevoked_SerialNotInCRL(t *testing.T) {
	ca, caKey := generateTestCA(t)
	revokedSerial := big.NewInt(12345)
	crlBytes := generateTestCRL(t, ca, caKey, revokedSerial)

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if IsRevoked(rl, big.NewInt(99999)) {
		t.Error("IsRevoked() = true, want false for non-revoked serial")
	}
}

func TestIsRevoked_EmptyCRL(t *testing.T) {
	ca, caKey := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey) // no revoked serials

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if IsRevoked(rl, big.NewInt(12345)) {
		t.Error("IsRevoked() = true, want false for empty CRL")
	}
}

func TestValidateNotRevoked_NotRevoked(t *testing.T) {
	ca, caKey := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey, big.NewInt(100))

	err := ValidateNotRevoked(crlBytes, ca, big.NewInt(200))
	if err != nil {
		t.Errorf("ValidateNotRevoked() error = %v, want nil", err)
	}
}

func TestValidateNotRevoked_Revoked(t *testing.T) {
	ca, caKey := generateTestCA(t)
	serial := big.NewInt(100)
	crlBytes := generateTestCRL(t, ca, caKey, serial)

	err := ValidateNotRevoked(crlBytes, ca, serial)
	if err != ErrRevoked {
		t.Errorf("ValidateNotRevoked() error = %v, want ErrRevoked", err)
	}
}

func TestValidateNotRevoked_ParseFails(t *testing.T) {
	ca, _ := generateTestCA(t)

	err := ValidateNotRevoked([]byte("garbage"), ca, big.NewInt(1))
	if err != ErrParseFailed {
		t.Errorf("ValidateNotRevoked() error = %v, want ErrParseFailed", err)
	}
}

func TestValidateNotRevoked_BadSignature(t *testing.T) {
	ca, caKey := generateTestCA(t)
	otherCA, _ := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey)

	err := ValidateNotRevoked(crlBytes, otherCA, big.NewInt(1))
	if err != ErrInvalidSignature {
		t.Errorf("ValidateNotRevoked() error = %v, want ErrInvalidSignature", err)
	}
}

func TestIsRevoked_MultipleRevoked(t *testing.T) {
	ca, caKey := generateTestCA(t)
	crlBytes := generateTestCRL(t, ca, caKey, big.NewInt(1), big.NewInt(2), big.NewInt(3))

	rl, err := Parse(crlBytes)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	for _, serial := range []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)} {
		if !IsRevoked(rl, serial) {
			t.Errorf("IsRevoked(serial=%v) = false, want true", serial)
		}
	}
	if IsRevoked(rl, big.NewInt(4)) {
		t.Error("IsRevoked(serial=4) = true, want false")
	}
}
