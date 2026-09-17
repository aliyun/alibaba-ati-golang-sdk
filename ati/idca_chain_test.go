package ati

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parsePEMCertsForTest(t *testing.T, pemData []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	return certs
}

func TestLoadEmbeddedIdcaChain(t *testing.T) {
	pool, err := loadEmbeddedIdcaChain()
	if err != nil {
		t.Fatalf("loadEmbeddedIdcaChain() error = %v", err)
	}
	if pool == nil {
		t.Fatal("loadEmbeddedIdcaChain() returned nil pool")
	}
	if len(pool.Subjects()) != 2 { //nolint:staticcheck // Subjects() is deprecated but adequate for a count check in tests.
		t.Errorf("embedded IDCA chain contains %d certs, want 2 (Root + Intermediate)", len(pool.Subjects()))
	}
}

func TestIdcaChainStructure(t *testing.T) {
	certs := parsePEMCertsForTest(t, embeddedIdcaChainPEM)
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates in embedded chain, got %d", len(certs))
	}

	root, intermediate := certs[0], certs[1]

	if !root.IsCA {
		t.Error("root certificate is not marked as CA")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("root certificate is not self-signed: %v", err)
	}

	if !intermediate.IsCA {
		t.Error("intermediate certificate is not marked as CA")
	}
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		t.Errorf("intermediate certificate is not signed by root: %v", err)
	}
}
