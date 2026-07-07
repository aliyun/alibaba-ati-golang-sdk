package verify

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPStatus represents the revocation status from an OCSP response.
type OCSPStatus int

const (
	OCSPStatusGood    OCSPStatus = iota
	OCSPStatusRevoked
	OCSPStatusUnknown
)

func (s OCSPStatus) String() string {
	switch s {
	case OCSPStatusGood:
		return "good"
	case OCSPStatusRevoked:
		return "revoked"
	case OCSPStatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// OCSPResult holds the result of an OCSP check per spec §8.3.
type OCSPResult struct {
	Status     OCSPStatus
	ProducedAt time.Time
	RevokedAt  time.Time
	Source     string // "stapled" or "active"
}

// OCSPChecker performs OCSP revocation checks via stapled response or active query.
type OCSPChecker struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewOCSPChecker creates a new OCSP checker.
func NewOCSPChecker(opts ...OCSPOption) *OCSPChecker {
	c := &OCSPChecker{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		timeout:    5 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// OCSPOption configures the OCSP checker.
type OCSPOption func(*OCSPChecker)

// WithOCSPHTTPClient sets a custom HTTP client for active OCSP queries.
func WithOCSPHTTPClient(client *http.Client) OCSPOption {
	return func(c *OCSPChecker) {
		c.httpClient = client
	}
}

// WithOCSPTimeout sets the timeout for active OCSP queries.
func WithOCSPTimeout(timeout time.Duration) OCSPOption {
	return func(c *OCSPChecker) {
		c.timeout = timeout
		c.httpClient.Timeout = timeout
	}
}

// CheckOCSP performs a dual-channel OCSP check per spec §8.3.
// It first tries the stapled response, then falls back to an active query.
func (c *OCSPChecker) CheckOCSP(ctx context.Context, cert *x509.Certificate, issuer *x509.Certificate, stapledResp []byte) (*OCSPResult, error) {
	if cert == nil {
		return nil, fmt.Errorf("ocsp: certificate is nil")
	}
	if issuer == nil {
		return nil, fmt.Errorf("ocsp: issuer certificate is nil")
	}

	// Try stapled response first
	if len(stapledResp) > 0 {
		result, err := c.verifyStapledOCSP(stapledResp, cert, issuer)
		if err == nil {
			return result, nil
		}
		// Stapled response invalid/expired — fall through to active query
	}

	// Active OCSP query
	return c.activeOCSPQuery(ctx, cert, issuer)
}

func (c *OCSPChecker) verifyStapledOCSP(raw []byte, cert, issuer *x509.Certificate) (*OCSPResult, error) {
	resp, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("ocsp: failed to parse stapled response: %w", err)
	}

	// Check freshness
	if time.Now().After(resp.NextUpdate) {
		return nil, fmt.Errorf("ocsp: stapled response expired at %s", resp.NextUpdate)
	}

	result := &OCSPResult{
		ProducedAt: resp.ProducedAt,
		Source:     "stapled",
	}

	switch resp.Status {
	case ocsp.Good:
		result.Status = OCSPStatusGood
	case ocsp.Revoked:
		result.Status = OCSPStatusRevoked
		result.RevokedAt = resp.RevokedAt
	default:
		result.Status = OCSPStatusUnknown
	}

	return result, nil
}

func (c *OCSPChecker) activeOCSPQuery(ctx context.Context, cert, issuer *x509.Certificate) (*OCSPResult, error) {
	if len(cert.OCSPServer) == 0 {
		return &OCSPResult{
			Status: OCSPStatusUnknown,
			Source: "active",
		}, nil
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("ocsp: failed to create request: %w", err)
	}

	ocspURL := cert.OCSPServer[0]
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return nil, fmt.Errorf("ocsp: failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ocsp: active query failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ocsp: responder returned status %d", httpResp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("ocsp: failed to read response: %w", err)
	}

	resp, err := ocsp.ParseResponseForCert(respBytes, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("ocsp: failed to parse active response: %w", err)
	}

	result := &OCSPResult{
		ProducedAt: resp.ProducedAt,
		Source:     "active",
	}

	switch resp.Status {
	case ocsp.Good:
		result.Status = OCSPStatusGood
	case ocsp.Revoked:
		result.Status = OCSPStatusRevoked
		result.RevokedAt = resp.RevokedAt
	default:
		result.Status = OCSPStatusUnknown
	}

	return result, nil
}
