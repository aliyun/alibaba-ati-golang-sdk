package crl

import (
	"crypto/x509"
	"errors"
	"math/big"
)

var (
	ErrRevoked          = errors.New("certificate serial is revoked")
	ErrInvalidSignature = errors.New("CRL signature verification failed")
	ErrParseFailed      = errors.New("failed to parse CRL")
)

// Parse parses a DER-encoded CRL into a RevocationList.
func Parse(crlBytes []byte) (*x509.RevocationList, error) {
	rl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, ErrParseFailed
	}
	return rl, nil
}

// VerifySignature checks that the CRL was signed by the given issuer certificate.
func VerifySignature(rl *x509.RevocationList, issuer *x509.Certificate) error {
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// IsRevoked checks whether the given serial number appears in the CRL.
func IsRevoked(rl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range rl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// ValidateNotRevoked parses a CRL, verifies its signature against the issuer,
// and checks that the given serial number is not revoked.
func ValidateNotRevoked(crlBytes []byte, issuer *x509.Certificate, serial *big.Int) error {
	rl, err := Parse(crlBytes)
	if err != nil {
		return err
	}
	if err := VerifySignature(rl, issuer); err != nil {
		return err
	}
	if IsRevoked(rl, serial) {
		return ErrRevoked
	}
	return nil
}
