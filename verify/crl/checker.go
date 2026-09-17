package crl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
)

// Checker orchestrates CDP discovery, CRL fetching, and revocation validation.
type Checker struct {
	fetcher *Fetcher
}

// CheckerOption configures a Checker.
type CheckerOption func(*Checker)

// WithFetcher sets a custom fetcher for the checker.
func WithFetcher(f *Fetcher) CheckerOption {
	return func(c *Checker) {
		c.fetcher = f
	}
}

// NewChecker creates a CRL checker with optional configuration.
func NewChecker(opts ...CheckerOption) *Checker {
	c := &Checker{}
	for _, opt := range opts {
		opt(c)
	}
	if c.fetcher == nil {
		c.fetcher = NewFetcher()
	}
	return c
}

// Check performs a complete CRL revocation check on the leaf certificate.
// Flow: ResolveCDP → findIssuingCA → Fetch → ValidateNotRevoked
func (c *Checker) Check(ctx context.Context, leaf *x509.Certificate, chain []*x509.Certificate) Result {
	cdpResult := ResolveCDP(chain)
	switch cdpResult.Status {
	case CDPSkipped:
		return Result{Status: Skipped, Message: cdpResult.Message}
	case CDPFailed:
		return Result{Status: Failed, Message: cdpResult.Message}
	}

	issuer := findIssuingCA(leaf, chain)
	if issuer == nil {
		return Result{Status: Failed, Message: "issuing CA not found in chain", CDPURI: cdpResult.URI}
	}

	crlBytes, err := c.fetcher.Fetch(ctx, cdpResult.URI)
	if err != nil {
		return Result{Status: Failed, Message: fmt.Sprintf("CRL fetch failed: %v", err), CDPURI: cdpResult.URI}
	}

	if err := ValidateNotRevoked(crlBytes, issuer, leaf.SerialNumber); err != nil {
		if errors.Is(err, ErrRevoked) {
			return Result{Status: Revoked, Message: "certificate serial is revoked", CDPURI: cdpResult.URI}
		}
		return Result{Status: Failed, Message: fmt.Sprintf("CRL validation failed: %v", err), CDPURI: cdpResult.URI}
	}

	return Result{Status: Passed, Message: "certificate not revoked", CDPURI: cdpResult.URI}
}
