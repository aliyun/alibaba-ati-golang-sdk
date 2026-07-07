package verify

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// DefaultTrustedRADomains returns the default trusted Registration Authority domains.
func DefaultTrustedRADomains() []string {
	return []string{
		"tl.ansagent.cn",
	}
}

// URLErrorType represents the type of URL validation failure.
type URLErrorType int

const (
	// URLErrorHTTPScheme indicates the URL uses HTTP instead of HTTPS.
	URLErrorHTTPScheme URLErrorType = iota
	// URLErrorUntrustedDomain indicates the URL domain is not a trusted RA.
	URLErrorUntrustedDomain
	// URLErrorNonStandardPort indicates the URL uses a non-standard port.
	URLErrorNonStandardPort
	// URLErrorPathTraversal indicates the URL contains path traversal or query injection.
	URLErrorPathTraversal
)

// URLValidationError represents a badge URL validation failure.
type URLValidationError struct {
	Type   URLErrorType
	URL    string
	Reason string
}

// Error implements the error interface.
func (e *URLValidationError) Error() string {
	switch e.Type {
	case URLErrorHTTPScheme:
		return fmt.Sprintf("badge URL must use HTTPS: %s", e.URL)
	case URLErrorUntrustedDomain:
		return fmt.Sprintf("badge URL domain not trusted: %s", e.URL)
	case URLErrorNonStandardPort:
		return fmt.Sprintf("badge URL uses non-standard port: %s", e.URL)
	case URLErrorPathTraversal:
		return fmt.Sprintf("badge URL contains path traversal or query params: %s", e.URL)
	default:
		return fmt.Sprintf("badge URL validation error: %s", e.URL)
	}
}

// URLValidator validates badge URLs against trusted RA domains.
type URLValidator struct {
	trustedDomains []string
}

// NewURLValidator creates a new URLValidator with the given trusted domains.
func NewURLValidator(trustedDomains []string) *URLValidator {
	lower := make([]string, len(trustedDomains))
	for i, d := range trustedDomains {
		lower[i] = strings.ToLower(d)
	}
	return &URLValidator{trustedDomains: lower}
}

// NewDefaultURLValidator creates a URLValidator with default trusted RA domains.
func NewDefaultURLValidator() *URLValidator {
	return NewURLValidator(DefaultTrustedRADomains())
}

// Validate checks a badge URL against security requirements:
// 1. HTTPS required
// 2. Domain must be in trusted list (case-insensitive)
// 3. No non-standard port (only 443 or empty)
// 4. No path traversal (..) or query params
func (v *URLValidator) Validate(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &URLValidationError{
			Type:   URLErrorHTTPScheme,
			URL:    rawURL,
			Reason: err.Error(),
		}
	}

	// 1. HTTPS required
	if parsed.Scheme != "https" {
		return &URLValidationError{
			Type: URLErrorHTTPScheme,
			URL:  rawURL,
		}
	}

	// 2. Trusted domain check (case-insensitive)
	hostname := strings.ToLower(parsed.Hostname())
	if !v.isDomainTrusted(hostname) {
		return &URLValidationError{
			Type: URLErrorUntrustedDomain,
			URL:  rawURL,
		}
	}

	// 3. No non-standard port (allow 443 and 8180 for CNNIC TL)
	port := parsed.Port()
	if port != "" && port != "443" && port != "8180" {
		return &URLValidationError{
			Type: URLErrorNonStandardPort,
			URL:  rawURL,
		}
	}

	// 4. No path traversal or query injection
	if strings.Contains(parsed.Path, "..") {
		return &URLValidationError{
			Type: URLErrorPathTraversal,
			URL:  rawURL,
		}
	}
	if parsed.RawQuery != "" {
		return &URLValidationError{
			Type: URLErrorPathTraversal,
			URL:  rawURL,
		}
	}

	return nil
}

// isDomainTrusted checks if the hostname matches any trusted domain.
func (v *URLValidator) isDomainTrusted(hostname string) bool {
	return slices.Contains(v.trustedDomains, hostname)
}

// BuildBadgeURL extracts path and port from a badge TXT URL and combines them
// with the configured TL base URL to construct the final query address.
func BuildBadgeURL(badgeRawURL string, tlBaseURL string) (string, error) {
	badgeURL, err := url.Parse(badgeRawURL)
	if err != nil {
		return "", fmt.Errorf("invalid badge URL: %w", err)
	}

	baseURL, err := url.Parse(tlBaseURL)
	if err != nil {
		return "", fmt.Errorf("invalid TL base URL: %w", err)
	}

	port := badgeURL.Port()
	if port == "" {
		port = "443"
	}

	host := baseURL.Hostname()
	result := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
		Path:   badgeURL.Path,
	}
	return result.String(), nil
}

// RewriteBadgeURLHost replaces the hostname (and port) in a badge URL with
// the trusted TL host. This prevents DNS poisoning from redirecting badge
// fetches to a rogue server. The scheme and path are preserved.
func RewriteBadgeURLHost(rawURL, trustedHost string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid badge URL: %w", err)
	}
	origPort := parsed.Port()
	if origPort != "" {
		parsed.Host = trustedHost + ":" + origPort
	} else {
		parsed.Host = trustedHost
	}
	return parsed.String(), nil
}
