package verify

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// Default DNS configuration values.
const (
	defaultDNSTimeoutSeconds = 10
	defaultDNSCacheTTL       = 5 * time.Minute
)

// ErrRecordNotFound is returned when no matching badge record is found.
// This is not an error condition - it means the FQDN is not an ATI agent.
var ErrRecordNotFound = errors.New("no matching badge record found")

type dnsCacheEntry struct {
	result    interface{}
	createdAt time.Time
}

// StandardDNSResolver implements DNSResolver using Go's net.Resolver.
type StandardDNSResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
	cache    sync.Map
	cacheTTL time.Duration
}

// NewStandardDNSResolver creates a new StandardDNSResolver with default settings.
func NewStandardDNSResolver() *StandardDNSResolver {
	return &StandardDNSResolver{
		resolver: net.DefaultResolver,
		timeout:  defaultDNSTimeoutSeconds * time.Second,
		cacheTTL: defaultDNSCacheTTL,
	}
}

// WithResolver sets a custom net.Resolver.
func (r *StandardDNSResolver) WithResolver(resolver *net.Resolver) *StandardDNSResolver {
	r.resolver = resolver
	return r
}

// WithServerAddress points the resolver at a specific DNS server, given as
// "host" or "host:port" (port defaults to 53). An empty address is a no-op and
// keeps the system resolver configuration (/etc/resolv.conf).
func (r *StandardDNSResolver) WithServerAddress(addr string) *StandardDNSResolver {
	if addr == "" {
		return r
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, network, addr)
		},
	}
	return r
}

// WithTimeout sets the lookup timeout.
func (r *StandardDNSResolver) WithTimeout(timeout time.Duration) *StandardDNSResolver {
	r.timeout = timeout
	return r
}

// WithCacheTTL sets the DNS cache TTL. Default is 5 minutes.
func (r *StandardDNSResolver) WithCacheTTL(ttl time.Duration) *StandardDNSResolver {
	r.cacheTTL = ttl
	return r
}

// ClearCache clears all cached DNS results.
func (r *StandardDNSResolver) ClearCache() {
	r.cache.Range(func(key, _ interface{}) bool {
		r.cache.Delete(key)
		return true
	})
}

func (r *StandardDNSResolver) getCached(key string) (interface{}, bool) {
	v, ok := r.cache.Load(key)
	if !ok {
		return nil, false
	}
	entry := v.(*dnsCacheEntry)
	if time.Since(entry.createdAt) > r.cacheTTL {
		r.cache.Delete(key)
		return nil, false
	}
	return entry.result, true
}

func (r *StandardDNSResolver) setCache(key string, result interface{}) {
	r.cache.Store(key, &dnsCacheEntry{result: result, createdAt: time.Now()})
}

// LookupATIBadge queries _ati-badge TXT records for an FQDN.
// If _ati-badge returns NXDOMAIN/NotFound, falls back to _ra-badge.
// On hard errors (SERVFAIL/timeout), does NOT fallback.
func (r *StandardDNSResolver) LookupATIBadge(ctx context.Context, fqdn models.Fqdn) (DNSLookupResult, error) {
	cacheKey := "badge:" + fqdn.String()
	if cached, ok := r.getCached(cacheKey); ok {
		return cached.(DNSLookupResult), nil
	}

	// Try _ati-badge first
	result, err := r.lookupBadgeRecords(ctx, fqdn.ATIBadgeName(), BadgeRecordSourceATIBadge)
	if err != nil {
		return result, err
	}
	if result.Found {
		r.setCache(cacheKey, result)
		return result, nil
	}

	// Fallback to _ra-badge
	result, err = r.lookupBadgeRecords(ctx, fqdn.RaBadgeName(), BadgeRecordSourceRaBadge)
	if err == nil {
		r.setCache(cacheKey, result)
	}
	return result, err
}

// lookupBadgeRecords queries a specific DNS name for badge TXT records.
func (r *StandardDNSResolver) lookupBadgeRecords(ctx context.Context, queryName string, source BadgeRecordSource) (DNSLookupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	txts, err := r.resolver.LookupTXT(ctx, queryName)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return DNSLookupResult{Found: false}, nil
		}
		// Hard error (timeout, SERVFAIL, etc.)
		return r.handleLookupError(err, queryName)
	}

	var records []ATIBadgeRecord
	for _, txt := range txts {
		if record, parseErr := ParseATIBadgeRecord(txt); parseErr == nil {
			record.Source = source
			records = append(records, *record)
		}
	}

	if len(records) == 0 {
		return DNSLookupResult{Found: false}, nil
	}

	return DNSLookupResult{Found: true, Records: records}, nil
}

// handleLookupError converts net.DNSError to appropriate results.
func (r *StandardDNSResolver) handleLookupError(err error, queryName string) (DNSLookupResult, error) {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return DNSLookupResult{}, &DNSError{
			Type:   DNSErrorLookupFailed,
			Fqdn:   queryName,
			Reason: err.Error(),
		}
	}

	if dnsErr.IsNotFound {
		return DNSLookupResult{Found: false}, nil
	}

	if dnsErr.IsTimeout {
		return DNSLookupResult{}, &DNSError{Type: DNSErrorTimeout, Fqdn: queryName}
	}

	return DNSLookupResult{}, &DNSError{
		Type:   DNSErrorLookupFailed,
		Fqdn:   queryName,
		Reason: err.Error(),
	}
}

// FindBadgeForVersion finds the badge record matching a specific version.
// Prefers an exact version match; falls back to a versionless record if no exact match exists.
func (r *StandardDNSResolver) FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*ATIBadgeRecord, error) {
	records, err := GetATIBadgeRecords(ctx, r, fqdn)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	// First pass: exact version match
	for _, record := range records {
		if record.Version != nil && record.Version.Equal(version) {
			return &record, nil
		}
	}

	// Second pass: versionless record as fallback (matches any version)
	for _, record := range records {
		if record.Version == nil {
			return &record, nil
		}
	}

	return nil, ErrRecordNotFound
}

// FindPreferredBadge finds the preferred badge (newest version).
func (r *StandardDNSResolver) FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*ATIBadgeRecord, error) {
	records, err := GetATIBadgeRecords(ctx, r, fqdn)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	if len(records) == 0 {
		return nil, ErrRecordNotFound
	}

	// Sort by version descending (newest first), nil versions go last
	sort.Slice(records, func(i, j int) bool {
		vi := records[i].Version
		vj := records[j].Version

		if vi == nil && vj == nil {
			return false
		}
		if vi == nil {
			return false // nil goes last
		}
		if vj == nil {
			return true // non-nil comes first
		}
		return vi.Compare(*vj) > 0 // Higher version first
	})

	return &records[0], nil
}

// LookupATIDiscovery queries _ati TXT records for DNS discovery.
func (r *StandardDNSResolver) LookupATIDiscovery(ctx context.Context, fqdn models.Fqdn) (ATIDiscoveryResult, error) {
	cacheKey := "discovery:" + fqdn.String()
	if cached, ok := r.getCached(cacheKey); ok {
		return cached.(ATIDiscoveryResult), nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	queryName := fqdn.ATIDiscoveryName()
	txts, err := r.resolver.LookupTXT(ctx, queryName)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			result := ATIDiscoveryResult{Found: false}
			r.setCache(cacheKey, result)
			return result, nil
		}
		return ATIDiscoveryResult{}, &DNSError{
			Type:   DNSErrorLookupFailed,
			Fqdn:   queryName,
			Reason: err.Error(),
		}
	}

	var records []*ATIRecord
	for _, txt := range txts {
		if record, parseErr := ParseATIRecord(txt); parseErr == nil {
			records = append(records, record)
		}
	}

	result := ATIDiscoveryResult{Found: len(records) > 0, Records: records}
	r.setCache(cacheKey, result)
	return result, nil
}

// isNotFoundError checks if the error indicates record not found.
func isNotFoundError(err error) bool {
	var dnsErr *DNSError
	return errors.As(err, &dnsErr) && dnsErr.Type == DNSErrorNotFound
}
