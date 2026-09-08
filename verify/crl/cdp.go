package crl

import (
	"crypto/x509"
	"strings"
)

// CDPStatus represents the outcome of CDP resolution.
type CDPStatus int

const (
	CDPSkipped CDPStatus = iota // no CDP extension found in the chain
	CDPFound                    // valid HTTP(S) CDP URI found
	CDPFailed                   // CDP extension present but no valid HTTP(S) URI
)

// CDPResult holds the result of resolving a CRL Distribution Point.
type CDPResult struct {
	Status  CDPStatus
	URI     string
	Message string
}

// ResolveCDP extracts the first HTTP(S) CRL Distribution Point URI from the
// certificate chain. It checks the leaf certificate first, then walks up the chain.
func ResolveCDP(chain []*x509.Certificate) CDPResult {
	if len(chain) == 0 {
		return CDPResult{Status: CDPSkipped, Message: "empty certificate chain"}
	}

	for _, cert := range chain {
		if len(cert.CRLDistributionPoints) > 0 {
			for _, dp := range cert.CRLDistributionPoints {
				if isHTTPURI(dp) {
					return CDPResult{Status: CDPFound, URI: dp}
				}
			}
			return CDPResult{Status: CDPFailed, Message: "CDP present but no HTTP(S) URI found"}
		}
	}

	return CDPResult{Status: CDPSkipped, Message: "no CDP extension in certificate chain"}
}

// findIssuingCA locates the issuing CA certificate for the given leaf in the chain.
func findIssuingCA(leaf *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	for _, cert := range chain {
		if cert == leaf {
			continue
		}
		if err := leaf.CheckSignatureFrom(cert); err == nil {
			return cert
		}
	}
	return nil
}

func isHTTPURI(uri string) bool {
	return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
}
