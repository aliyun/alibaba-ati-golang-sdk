package verify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// IANA Root Zone Trust Anchor (Key Tag 20326, Algorithm 8, SHA-256)
// https://data.iana.org/root-anchors/root-anchors.xml
var defaultRootTrustAnchor = &dns.DS{
	Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
	KeyTag:     20326,
	Algorithm:  8,
	DigestType: 2,
	Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
}

// dnssecValidator performs local DNSSEC chain validation.
type dnssecValidator struct {
	server      string
	timeout     time.Duration
	trustAnchor *dns.DS
	cache       sync.Map // zone name -> *dnssecCacheEntry
}

type dnssecCacheEntry struct {
	keys    []*dns.DNSKEY
	expires time.Time
}

// newDNSSECValidator creates a new DNSSEC validator.
func newDNSSECValidator(server string, timeout time.Duration, trustAnchor *dns.DS) *dnssecValidator {
	if trustAnchor == nil {
		trustAnchor = defaultRootTrustAnchor
	}
	return &dnssecValidator{
		server:      server,
		timeout:     timeout,
		trustAnchor: trustAnchor,
	}
}

// validateRRset validates DNSSEC signatures for an RRset by walking the chain to the root.
// Returns true if the full chain is validated, false if there's an insecure delegation.
func (v *dnssecValidator) validateRRset(ctx context.Context, rrset []dns.RR, rrsigs []*dns.RRSIG) (bool, error) {
	if len(rrset) == 0 || len(rrsigs) == 0 {
		return false, nil // No signatures = can't validate
	}

	// Find a valid RRSIG for this RRset
	rrsig := rrsigs[0] // Use first matching RRSIG
	zone := rrsig.SignerName

	// Validate from the signer zone up to root
	return v.validateZoneChain(ctx, zone, rrset, rrsig)
}

// validateZoneChain validates: RRSIG(rrset) → zone DNSKEY → parent DS → ... → root
func (v *dnssecValidator) validateZoneChain(ctx context.Context, zone string, rrset []dns.RR, rrsig *dns.RRSIG) (bool, error) {
	// 1. Get DNSKEY for the zone
	dnskeys, err := v.fetchDNSKEYs(ctx, zone)
	if err != nil {
		return false, err
	}
	if len(dnskeys) == 0 {
		return false, nil // insecure delegation
	}

	// 2. Handle wildcard expansion: if RRSIG labels < owner name labels,
	// the record was synthesized from a wildcard. Replace owner names with
	// the wildcard form for signature verification, then restore them.
	verifyRRset := rrset
	if len(rrset) > 0 {
		ownerLabels := dns.CountLabel(rrset[0].Header().Name)
		if int(rrsig.Labels) < ownerLabels {
			verifyRRset = make([]dns.RR, len(rrset))
			copy(verifyRRset, rrset)
			wildcardName := wildcardOwner(rrset[0].Header().Name, int(rrsig.Labels))
			for i := range verifyRRset {
				verifyRRset[i] = dns.Copy(verifyRRset[i])
				verifyRRset[i].Header().Name = wildcardName
			}
		}
	}

	// 3. Find the ZSK that signed this RRset (matching KeyTag)
	verified := false
	for _, key := range dnskeys {
		if key.KeyTag() == rrsig.KeyTag {
			if err := rrsig.Verify(key, verifyRRset); err == nil {
				verified = true
				break
			}
		}
	}
	if !verified {
		return false, fmt.Errorf("RRSIG verification failed for zone %s (key tag %d)", zone, rrsig.KeyTag)
	}

	// 4. Validate the DNSKEY set itself (must be signed by a KSK)
	if err := v.validateDNSKEYSet(ctx, zone, dnskeys); err != nil {
		return false, err
	}

	// 5. If this is the root zone, verify against trust anchor
	if zone == "." {
		return v.verifyRootKeys(dnskeys)
	}

	// 6. Get DS from parent, verify KSK matches DS
	return v.validateDSChain(ctx, zone, dnskeys)
}

// fetchDNSKEYs fetches and returns DNSKEY records for a zone (with caching).
func (v *dnssecValidator) fetchDNSKEYs(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	// Check cache first
	if entry, ok := v.cache.Load(zone); ok {
		ce := entry.(*dnssecCacheEntry)
		if time.Now().Before(ce.expires) {
			return ce.keys, nil
		}
		v.cache.Delete(zone)
	}

	// Query DNSKEY
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true

	resp, err := v.exchange(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNSKEY for %s: %w", zone, err)
	}

	var keys []*dns.DNSKEY
	var minTTL uint32 = 86400
	for _, rr := range resp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}

	// Cache the keys
	if len(keys) > 0 {
		v.cache.Store(zone, &dnssecCacheEntry{
			keys:    keys,
			expires: time.Now().Add(time.Duration(minTTL) * time.Second),
		})
	}

	return keys, nil
}

// validateDNSKEYSet verifies that the DNSKEY RRset is self-signed by a KSK.
func (v *dnssecValidator) validateDNSKEYSet(ctx context.Context, zone string, dnskeys []*dns.DNSKEY) error {
	// Query DNSKEY with RRSIG
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true

	resp, err := v.exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to query DNSKEY RRSIG for %s: %w", zone, err)
	}

	// Find RRSIG for DNSKEY
	var dnskeyRRset []dns.RR
	var rrsigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			dnskeyRRset = append(dnskeyRRset, rr)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDNSKEY {
				rrsigs = append(rrsigs, r)
			}
		}
	}

	if len(rrsigs) == 0 {
		return fmt.Errorf("no RRSIG for DNSKEY in zone %s", zone)
	}

	// Verify DNSKEY RRset is signed by one of the KSKs
	for _, rrsig := range rrsigs {
		for _, key := range dnskeys {
			if key.Flags == 257 && key.KeyTag() == rrsig.KeyTag { // KSK
				if err := rrsig.Verify(key, dnskeyRRset); err == nil {
					return nil // Valid self-signature
				}
			}
		}
	}

	return fmt.Errorf("DNSKEY self-signature validation failed for zone %s", zone)
}

// validateDSChain gets DS from parent zone and validates the KSK hash matches.
func (v *dnssecValidator) validateDSChain(ctx context.Context, zone string, dnskeys []*dns.DNSKEY) (bool, error) {
	// Query DS record from parent
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = true

	resp, err := v.exchange(ctx, msg)
	if err != nil {
		return false, fmt.Errorf("failed to query DS for %s: %w", zone, err)
	}

	var dsRecords []*dns.DS
	var dsRRset []dns.RR
	var dsRRSIGs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.DS:
			dsRecords = append(dsRecords, r)
			dsRRset = append(dsRRset, rr)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDS {
				dsRRSIGs = append(dsRRSIGs, r)
			}
		}
	}

	if len(dsRecords) == 0 {
		return false, nil // Insecure delegation — no DS means chain breaks here
	}

	// Verify at least one KSK matches a DS record
	matched := false
	for _, ds := range dsRecords {
		for _, key := range dnskeys {
			if key.Flags == 257 { // KSK
				computed := key.ToDS(ds.DigestType)
				if computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
					matched = true
					break
				}
			}
		}
		if matched {
			break
		}
	}

	if !matched {
		return false, fmt.Errorf("no KSK in zone %s matches parent DS record", zone)
	}

	// Now validate the DS RRset itself — recurse to parent zone
	if len(dsRRSIGs) == 0 {
		return false, fmt.Errorf("no RRSIG for DS records of %s", zone)
	}

	parentZone := parentOf(zone)
	return v.validateZoneChain(ctx, parentZone, dsRRset, dsRRSIGs[0])
}

// verifyRootKeys verifies that one of the root DNSKEY matches the trust anchor.
func (v *dnssecValidator) verifyRootKeys(dnskeys []*dns.DNSKEY) (bool, error) {
	for _, key := range dnskeys {
		if key.Flags == 257 { // KSK
			computed := key.ToDS(v.trustAnchor.DigestType)
			if computed != nil && strings.EqualFold(computed.Digest, v.trustAnchor.Digest) {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("no root DNSKEY matches trust anchor (key tag %d)", v.trustAnchor.KeyTag)
}

const daneMaxRetries = 2

// exchange performs a DNS query with timeout retry and TCP fallback if truncated.
func (v *dnssecValidator) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	for attempt := 0; attempt <= daneMaxRetries; attempt++ {
		if attempt > 0 {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			slog.Info("[DANE] retrying DNS query", "attempt", attempt+1, "server", v.server, "question", msg.Question[0].Name)
		}

		resp, err := v.doExchange(ctx, msg)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if !isTimeout(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("DNS query timeout after %d retries: %w", daneMaxRetries, lastErr)
}

func (v *dnssecValidator) doExchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: v.timeout,
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < client.Timeout {
			client.Timeout = remaining
		}
	}

	resp, _, err := client.ExchangeContext(ctx, msg, v.server)
	if err != nil {
		return nil, err
	}

	// TCP fallback if truncated
	if resp.Truncated {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: v.timeout,
		}
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining < tcpClient.Timeout {
				tcpClient.Timeout = remaining
			}
		}
		resp, _, err = tcpClient.ExchangeContext(ctx, msg, v.server)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout")
}

// wildcardOwner reconstructs the wildcard owner name from an expanded name.
// e.g., "_ati-identity._tls.www.ats-client.asia." with sigLabels=5
// → "*.ats-client.asia." (strip labels beyond sigLabels, prepend "*").
func wildcardOwner(name string, sigLabels int) string {
	labels := dns.SplitDomainName(name)
	if sigLabels >= len(labels) {
		return name
	}
	return "*." + strings.Join(labels[len(labels)-sigLabels:], ".") + "."
}

// parentOf returns the parent zone of the given zone.
// e.g., "example.com." -> "com.", "com." -> "."
func parentOf(zone string) string {
	zone = dns.Fqdn(zone)
	if zone == "." {
		return "."
	}
	idx := strings.Index(zone, ".")
	if idx < 0 {
		return "."
	}
	parent := zone[idx+1:]
	if parent == "" {
		return "."
	}
	return parent
}
