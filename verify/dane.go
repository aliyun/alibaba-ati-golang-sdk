package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/miekg/dns"
)

// TLSARecord represents a parsed TLSA DNS record.
type TLSARecord struct {
	// Usage is the certificate usage field (DANE-TA=2, DANE-EE=3).
	Usage uint8
	// Selector is the selector field (full cert=0, SubjectPublicKeyInfo=1).
	Selector uint8
	// MatchingType is the matching type (exact=0, SHA-256=1, SHA-512=2).
	MatchingType uint8
	// CertHash is the hex-encoded, lowercase certificate association data.
	CertHash string
}

// TLSALookupResult represents the result of a TLSA DNS lookup.
type TLSALookupResult struct {
	// Found indicates whether any TLSA records were found.
	Found bool
	// Records contains the found TLSA records.
	Records []TLSARecord
	// DNSSECValid indicates whether the response was DNSSEC-validated.
	DNSSECValid bool
}

// DANEOutcomeType represents the type of DANE verification outcome.
type DANEOutcomeType int

const (
	// DANEVerified indicates DANE verification passed (DNSSEC valid, TLSA match).
	DANEVerified DANEOutcomeType = iota
	// DANEMismatch indicates TLSA records exist but no fingerprint matched.
	DANEMismatch
	// DANESkipped indicates DANE was skipped (records exist but no DNSSEC).
	DANESkipped
	// DANEDNSSECFailed indicates DNSSEC validation explicitly failed.
	DANEDNSSECFailed
	// DANENoRecords indicates no TLSA records were found.
	DANENoRecords
	// DANELookupError indicates a DNS lookup error occurred.
	DANELookupError
)

// String returns the string representation of a DANEOutcomeType.
func (t DANEOutcomeType) String() string {
	switch t {
	case DANEVerified:
		return "DANEVerified"
	case DANEMismatch:
		return "DANEMismatch"
	case DANESkipped:
		return "DANESkipped"
	case DANEDNSSECFailed:
		return "DANEDNSSECFailed"
	case DANENoRecords:
		return "DANENoRecords"
	case DANELookupError:
		return "DANELookupError"
	default:
		return "unknown"
	}
}

// DANEOutcome represents the result of a DANE/TLSA verification.
type DANEOutcome struct {
	// Type is the outcome type.
	Type DANEOutcomeType
	// Records contains the TLSA records found (if any).
	Records []TLSARecord
	// CertHashUsed is the hex-encoded cert hash that was computed and compared against TLSA records.
	CertHashUsed string
	// Error is the underlying error (if any).
	Error error
}

// IsPass reports whether the connection should be allowed under a fail-open
// DANE policy. It is true when verification succeeded (DANEVerified) and also
// in the benign cases where DANE cannot make a negative assertion: no TLSA
// records published (DANENoRecords) or records present without a DNSSEC chain
// (DANESkipped). Only an affirmative negative — a fingerprint mismatch or an
// explicit DNSSEC failure — is treated as non-passing.
func (o *DANEOutcome) IsPass() bool {
	switch o.Type {
	case DANEVerified, DANESkipped, DANENoRecords:
		return true
	default:
		return false
	}
}

// IsReject reports whether the connection must be refused. Only an affirmative
// negative assertion rejects: TLSA records exist under a valid DNSSEC chain but
// none match the presented certificate (DANEMismatch), or DNSSEC validation
// explicitly failed (DANEDNSSECFailed). A bare lookup error is not a rejection —
// callers apply their own fail-open/fail-closed policy via IsError.
func (o *DANEOutcome) IsReject() bool {
	switch o.Type {
	case DANEMismatch, DANEDNSSECFailed:
		return true
	default:
		return false
	}
}

// IsError returns true if a DNS lookup error prevented verification.
// When true, the caller should apply their failure policy (fail-open vs fail-closed).
func (o *DANEOutcome) IsError() bool {
	return o.Type == DANELookupError
}

// DANEResolver is the interface for DANE/TLSA DNS resolution.
type DANEResolver interface {
	// LookupTLSA queries TLSA records for the given FQDN and port (_<port>._tcp.<fqdn>).
	LookupTLSA(ctx context.Context, fqdn models.Fqdn, port uint16) (TLSALookupResult, error)
	// LookupIdentityTLSA queries identity TLSA records (_ati-identity._tls.<fqdn>).
	LookupIdentityTLSA(ctx context.Context, fqdn models.Fqdn) (TLSALookupResult, error)
}

// DANEVerifier verifies certificates against DANE/TLSA records.
type DANEVerifier struct {
	resolver DANEResolver
}

// NewDANEVerifier creates a new DANEVerifier with the given resolver.
func NewDANEVerifier(resolver DANEResolver) *DANEVerifier {
	return &DANEVerifier{resolver: resolver}
}

// tlsaUsageDANEEE is the DANE-EE (domain-issued certificate) usage type.
const tlsaUsageDANEEE = 3

// Verify performs DANE/TLSA verification for a server certificate.
// Queries _<port>._tcp.<fqdn> TLSA records.
func (d *DANEVerifier) Verify(ctx context.Context, fqdn models.Fqdn, port uint16, cert *CertIdentity) *DANEOutcome {
	return d.verifyWithLookup(ctx, fqdn, cert, func() (TLSALookupResult, error) {
		return d.resolver.LookupTLSA(ctx, fqdn, port)
	})
}

// VerifyIdentity performs DANE/TLSA verification for a client identity certificate.
// Queries _ati-identity._tls.<fqdn> TLSA records.
func (d *DANEVerifier) VerifyIdentity(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) *DANEOutcome {
	return d.verifyWithLookup(ctx, fqdn, cert, func() (TLSALookupResult, error) {
		return d.resolver.LookupIdentityTLSA(ctx, fqdn)
	})
}

func (d *DANEVerifier) verifyWithLookup(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, lookup func() (TLSALookupResult, error)) *DANEOutcome {
	if cert == nil {
		return &DANEOutcome{Type: DANELookupError, Error: errors.New("nil certificate identity")}
	}

	result, err := lookup()
	if err != nil {
		var daneErr *DANEError
		if errors.As(err, &daneErr) && daneErr.Type == DANEErrorDNSSECFailed {
			return &DANEOutcome{Type: DANEDNSSECFailed, Error: err}
		}
		return &DANEOutcome{Type: DANELookupError, Error: err}
	}

	if !result.Found {
		return &DANEOutcome{Type: DANENoRecords, Error: fmt.Errorf("no TLSA records found for %s", fqdn.String())}
	}

	if !result.DNSSECValid {
		return &DANEOutcome{Type: DANESkipped, Records: result.Records, Error: fmt.Errorf("TLSA records found but DNSSEC validation failed for %s", fqdn.String())}
	}

	// Compare cert fingerprint against DANE-EE (Usage=3) TLSA records.
	// Selector=0: match full certificate DER hash
	// Selector=1: match SubjectPublicKeyInfo (SPKI) hash
	certFullHex := strings.ToLower(cert.Fingerprint.ToHex())
	spkiHex := strings.ToLower(cert.SPKIFingerprint.ToHex())
	var lastCertHex string

	for _, rec := range result.Records {
		if rec.Usage != tlsaUsageDANEEE {
			continue
		}

		var certHex string
		switch rec.Selector {
		case 0:
			certHex = certFullHex
		case 1:
			certHex = spkiHex
		default:
			continue
		}
		lastCertHex = certHex

		if strings.ToLower(rec.CertHash) == certHex {
			return &DANEOutcome{Type: DANEVerified, Records: result.Records, CertHashUsed: certHex}
		}
	}

	if lastCertHex == "" {
		lastCertHex = spkiHex
	}
	return &DANEOutcome{
		Type:         DANEMismatch,
		Records:      result.Records,
		CertHashUsed: lastCertHex,
		Error:        fmt.Errorf("TLSA fingerprint mismatch: cert(full)=%s, cert(spki)=%s, TLSA records have no match", certFullHex, spkiHex),
	}
}

// DANEResolverOption configures a StandardDANEResolver.
type DANEResolverOption func(*StandardDANEResolver)

// WithDANEServer sets the DNS server address for TLSA lookups.
// The server is used as the recursive resolver for fetching DNS records
// during local DNSSEC chain validation.
func WithDANEServer(server string) DANEResolverOption {
	return func(r *StandardDANEResolver) {
		r.server = server
	}
}

// WithDANETimeout sets the timeout for TLSA DNS lookups.
func WithDANETimeout(timeout time.Duration) DANEResolverOption {
	return func(r *StandardDANEResolver) {
		r.timeout = timeout
	}
}

// WithDANETrustAnchor sets a custom root trust anchor for DNSSEC validation (mainly for testing).
func WithDANETrustAnchor(ds *dns.DS) DANEResolverOption {
	return func(r *StandardDANEResolver) {
		r.trustAnchor = ds
	}
}

const (
	defaultDANETimeout = 5 * time.Second
	// edns0BufSize is the EDNS0 UDP buffer size for DNSSEC-aware queries.
	edns0BufSize = 4096
	// defaultDANEServer is the DNS server used for DANE/TLSA lookups when none is
	// configured. DANE requires an upstream that returns DNSSEC records (RRSIG),
	// so we default to a known DNSSEC-capable public resolver rather than the
	// host's /etc/resolv.conf, which is often a non-validating corporate resolver.
	// Callers can override via WithDANEServer.
	defaultDANEServer = "8.8.8.8:53"
)

// StandardDANEResolver performs real DNSSEC-aware TLSA lookups using miekg/dns.
// It performs local DNSSEC chain validation instead of relying on the recursive
// resolver's AD flag, making it work correctly with non-validating resolvers.
type StandardDANEResolver struct {
	server      string
	timeout     time.Duration
	validator   *dnssecValidator // local DNSSEC chain validator
	trustAnchor *dns.DS          // custom trust anchor (nil = use default)
}

// NewStandardDANEResolver creates a new StandardDANEResolver with the given options.
func NewStandardDANEResolver(opts ...DANEResolverOption) *StandardDANEResolver {
	r := &StandardDANEResolver{
		server:  defaultDANEServer,
		timeout: defaultDANETimeout,
	}
	for _, opt := range opts {
		opt(r)
	}
	// Initialize DNSSEC validator for local chain validation
	r.validator = newDNSSECValidator(r.server, r.timeout, r.trustAnchor)
	return r
}

// LookupTLSA queries TLSA records for the given FQDN and port (_<port>._tcp.<fqdn>).
// It performs local DNSSEC chain validation instead of relying on the AD flag.
func (r *StandardDANEResolver) LookupTLSA(ctx context.Context, fqdn models.Fqdn, port uint16) (TLSALookupResult, error) {
	tlsaName := fqdn.TlsaName(port) + "."
	return r.lookupTLSAByName(ctx, tlsaName, fqdn.String())
}

// LookupIdentityTLSA queries identity TLSA records (_ati-identity._tls.<fqdn>).
func (r *StandardDANEResolver) LookupIdentityTLSA(ctx context.Context, fqdn models.Fqdn) (TLSALookupResult, error) {
	tlsaName := fqdn.IdentityTLSAName() + "."
	return r.lookupTLSAByName(ctx, tlsaName, fqdn.String())
}

func (r *StandardDANEResolver) lookupTLSAByName(ctx context.Context, tlsaName, fqdnStr string) (TLSALookupResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(tlsaName, dns.TypeTLSA)
	msg.SetEdns0(edns0BufSize, true)
	msg.RecursionDesired = true

	resp, err := r.validator.exchange(ctx, msg)
	if err != nil {
		return TLSALookupResult{}, &DANEError{
			Type:   DANEErrorLookupFailed,
			Fqdn:   fqdnStr,
			Reason: err.Error(),
		}
	}

	if resp.Rcode == dns.RcodeServerFailure {
		return TLSALookupResult{}, &DANEError{
			Type:   DANEErrorDNSSECFailed,
			Fqdn:   fqdnStr,
			Reason: "SERVFAIL response (possible DNSSEC validation failure)",
		}
	}

	if resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0 {
		return TLSALookupResult{Found: false}, nil
	}

	var records []TLSARecord
	var tlsaRRset []dns.RR
	var rrsigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.TLSA:
			records = append(records, TLSARecord{
				Usage:        v.Usage,
				Selector:     v.Selector,
				MatchingType: v.MatchingType,
				CertHash:     strings.ToLower(v.Certificate),
			})
			tlsaRRset = append(tlsaRRset, rr)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeTLSA {
				rrsigs = append(rrsigs, v)
			}
		}
	}

	if len(records) == 0 {
		return TLSALookupResult{Found: false}, nil
	}

	slog.Info("[DANE] TLSA lookup", "query", tlsaName, "server", r.server, "records", len(records), "rrsigs", len(rrsigs))

	dnssecValid := false
	if len(rrsigs) > 0 {
		valid, err := r.validator.validateRRset(ctx, tlsaRRset, rrsigs)
		if err == nil && valid {
			dnssecValid = true
			slog.Info("[DANE] DNSSEC validation PASSED", "query", tlsaName)
		} else {
			slog.Warn("[DANE] DNSSEC validation FAILED", "query", tlsaName, "valid", valid, "error", err)
		}
	} else {
		slog.Warn("[DANE] no RRSIG in response", "query", tlsaName)
	}

	return TLSALookupResult{
		Found:       true,
		Records:     records,
		DNSSECValid: dnssecValid,
	}, nil
}
