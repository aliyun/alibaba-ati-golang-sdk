package verify

import (
	"context"
	"sync"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// DiscoveryResult holds all DNS discovery results per spec §4.6.
type DiscoveryResult struct {
	AgentCardURL    string
	TLQueryURL      string
	IdentityTLSA    []TLSARecord
	ServerTLSA      []TLSARecord
	HTTPSParams     *SVCBResult
	SelectedVersion *models.Version
	DNSSECStatus    string // "fully_validated" | "insecure" | "bogus"
	AgentID         string
}

// ParallelDiscovery performs all stage-1 DNS queries in parallel per spec §10.1.
// It queries _ati, _ati-badge, TLSA, and HTTPS/SVCB concurrently.
func ParallelDiscovery(ctx context.Context, fqdn models.Fqdn, resolver DNSResolver, daneResolver DANEResolver) (*DiscoveryResult, error) {
	result := &DiscoveryResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error

	// Query _ati TXT (required)
	wg.Add(1)
	go func() {
		defer wg.Done()
		disc, err := resolver.LookupATIDiscovery(ctx, fqdn)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		if disc.Found && len(disc.Records) > 0 {
			result.AgentID = disc.Records[0].ID
			if disc.Records[0].URL != "" {
				result.AgentCardURL = disc.Records[0].URL
			}
		}
	}()

	// Query _ati-badge TXT
	wg.Add(1)
	go func() {
		defer wg.Done()
		badge, err := resolver.FindPreferredBadge(ctx, fqdn)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			return // badge lookup failure is not fatal
		}
		if badge != nil {
			result.TLQueryURL = badge.URL
			result.SelectedVersion = badge.Version
		}
	}()

	// Query TLSA records (if DANE resolver available)
	if daneResolver != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tlsaResult, err := daneResolver.LookupTLSA(ctx, fqdn, 443)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				return
			}
			if tlsaResult.Found {
				result.IdentityTLSA = tlsaResult.Records
				if tlsaResult.DNSSECValid {
					result.DNSSECStatus = "fully_validated"
				} else {
					result.DNSSECStatus = "insecure"
				}
			}
		}()
	}

	wg.Wait()

	if result.AgentID == "" && firstErr != nil {
		return nil, firstErr
	}
	if result.AgentID == "" {
		return nil, NewANSError(CodeDNSCoreRecordMissing, SeverityHard, StageDNSDiscovery,
			"no _ati record found for "+fqdn.String())
	}

	return result, nil
}
