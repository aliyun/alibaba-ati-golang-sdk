package crl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	defaultMaxAge     = 12 * time.Hour
	defaultHTTPTimeout = 30 * time.Second
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
	mu         sync.Mutex
	cache      map[string]*cachedEntry
	httpClient *http.Client
	maxAge     time.Duration
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("crl fetch: read body failed: %w", err)
	}

	ttl := f.maxAge
	rl, parseErr := Parse(data)
	if parseErr == nil && !rl.NextUpdate.IsZero() {
		nextUpdateTTL := time.Until(rl.NextUpdate)
		if nextUpdateTTL > 0 && nextUpdateTTL < ttl {
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
