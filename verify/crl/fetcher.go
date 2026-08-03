package crl

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	defaultMaxAge      = 12 * time.Hour
	defaultHTTPTimeout = 30 * time.Second
	// maxCRLBodySize caps how much of a CRL response we read into memory,
	// guarding against memory-exhaustion DoS from an oversized/malicious response.
	maxCRLBodySize = 10 * 1024 * 1024 // 10MiB
)

type cachedEntry struct {
	data      []byte
	fetchedAt time.Time
	ttl       time.Duration
}

func (e *cachedEntry) isExpired() bool {
	return time.Since(e.fetchedAt) > e.ttl
}

// Fetcher downloads and caches CRL data from CDP URIs.
type Fetcher struct {
	mu                   sync.Mutex
	cache                map[string]*cachedEntry
	httpClient           *http.Client
	maxAge               time.Duration
	allowPrivateNetworks bool
}

// FetcherOption configures a Fetcher.
type FetcherOption func(*Fetcher)

// WithHTTPClient sets a custom HTTP client for CRL downloads.
func WithHTTPClient(client *http.Client) FetcherOption {
	return func(f *Fetcher) {
		f.httpClient = client
	}
}

// WithMaxAge sets the maximum cache age for CRL entries.
func WithMaxAge(d time.Duration) FetcherOption {
	return func(f *Fetcher) {
		f.maxAge = d
	}
}

// WithAllowPrivateNetworks disables the SSRF guard that otherwise rejects CDP
// URIs resolving to loopback/private/link-local/metadata addresses. CDP URIs
// are read from the peer's certificate chain, so the guard defaults to on in
// production; tests that fetch from local httptest servers must opt out.
func WithAllowPrivateNetworks(allow bool) FetcherOption {
	return func(f *Fetcher) {
		f.allowPrivateNetworks = allow
	}
}

// NewFetcher creates a CRL fetcher with optional configuration.
func NewFetcher(opts ...FetcherOption) *Fetcher {
	f := &Fetcher{
		cache:  make(map[string]*cachedEntry),
		maxAge: defaultMaxAge,
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Fetch retrieves CRL data from the given CDP URI. Results are cached based on
// the CRL's NextUpdate field (capped at maxAge).
func (f *Fetcher) Fetch(ctx context.Context, cdpURI string) ([]byte, error) {
	f.mu.Lock()
	if entry, ok := f.cache[cdpURI]; ok && !entry.isExpired() {
		f.mu.Unlock()
		return entry.data, nil
	}
	f.mu.Unlock()

	if !f.allowPrivateNetworks {
		if err := guardAgainstSSRF(cdpURI); err != nil {
			return nil, fmt.Errorf("crl fetch: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cdpURI, nil)
	if err != nil {
		return nil, fmt.Errorf("crl fetch: invalid URI %q: %w", cdpURI, err)
	}
	req.Header.Set("Accept", "application/pkix-crl")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crl fetch: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crl fetch: HTTP %d from %s", resp.StatusCode, cdpURI)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("crl fetch: read body failed: %w", err)
	}
	if len(data) > maxCRLBodySize {
		return nil, fmt.Errorf("crl fetch: response from %s exceeds %d byte limit", cdpURI, maxCRLBodySize)
	}

	ttl := f.maxAge
	rl, parseErr := Parse(data)
	if parseErr == nil && !rl.NextUpdate.IsZero() {
		nextUpdateTTL := time.Until(rl.NextUpdate)
		switch {
		case nextUpdateTTL <= 0:
			// NextUpdate has already passed: the CRL is stale, so force an
			// immediate re-fetch on the next call instead of caching it for
			// defaultMaxAge (matches Java CrlFetcher.computeCacheTtl).
			ttl = 0
		case nextUpdateTTL < ttl:
			ttl = nextUpdateTTL
		}
	}

	f.mu.Lock()
	f.cache[cdpURI] = &cachedEntry{
		data:      data,
		fetchedAt: time.Now(),
		ttl:       ttl,
	}
	f.mu.Unlock()

	return data, nil
}

// guardAgainstSSRF rejects CDP URIs whose host resolves to a loopback,
// private, link-local (which covers cloud metadata endpoints such as
// 169.254.169.254), or otherwise non-routable address. CDP URIs are read from
// the CRLDistributionPoints extension of the peer's certificate chain — an
// input the connecting peer can influence — so the fetch target must not be
// assumed to point only at public CRL infrastructure.
func guardAgainstSSRF(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid CDP URI %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("CDP URI %q has no host", rawURL)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve CDP host %q: %w", host, err)
	}
	for _, ip := range ips {
		if isDisallowedTarget(ip) {
			return fmt.Errorf("CDP host %q resolves to disallowed address %s", host, ip)
		}
	}
	return nil
}

func isDisallowedTarget(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}
