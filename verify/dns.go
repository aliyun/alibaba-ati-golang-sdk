package verify

import (
	"context"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// DNSLookupResult represents the result of a DNS lookup.
type DNSLookupResult struct {
	// Found indicates whether records were found.
	Found bool
	// Records contains the found records (empty if not found).
	Records []ATIBadgeRecord
}

// ATIDiscoveryResult represents the result of an _ati TXT DNS lookup.
type ATIDiscoveryResult struct {
	Found   bool
	Records []*ATIRecord
}

// DNSResolver is the interface for DNS resolution.
type DNSResolver interface {
	// LookupATIBadge queries _ati-badge TXT records for an FQDN.
	LookupATIBadge(ctx context.Context, fqdn models.Fqdn) (DNSLookupResult, error)

	// LookupATIDiscovery queries _ati TXT records for an FQDN.
	LookupATIDiscovery(ctx context.Context, fqdn models.Fqdn) (ATIDiscoveryResult, error)

	// FindBadgeForVersion finds the badge record matching a specific version.
	FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*ATIBadgeRecord, error)

	// FindPreferredBadge finds the preferred badge (newest version).
	FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*ATIBadgeRecord, error)
}

// GetATIBadgeRecords is a convenience method that returns records or error for not found.
func GetATIBadgeRecords(ctx context.Context, resolver DNSResolver, fqdn models.Fqdn) ([]ATIBadgeRecord, error) {
	result, err := resolver.LookupATIBadge(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if !result.Found {
		return nil, &DNSError{Type: DNSErrorNotFound, Fqdn: fqdn.String()}
	}
	return result.Records, nil
}
