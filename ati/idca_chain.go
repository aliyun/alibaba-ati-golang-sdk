package ati

import (
	"crypto/x509"
	_ "embed"
	"fmt"
)

//go:embed idca/idca-chain.crt
var embeddedIdcaChainPEM []byte

// loadEmbeddedIdcaChain parses the SDK-shipped IDCA Chain (Root + Intermediate)
// into a CertPool, used as the default client-certificate trust anchor when no
// custom CA bundle is configured via WithClientCA.
func loadEmbeddedIdcaChain() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(embeddedIdcaChainPEM) {
		return nil, fmt.Errorf("embedded IDCA chain contains no valid PEM certificates")
	}
	return pool, nil
}
