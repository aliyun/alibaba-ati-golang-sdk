package verify

import (
	"fmt"
	"net/url"
)

// RewriteBadgeURLHost replaces only the hostname in a badge URL with the
// trusted TL host, preserving the original port from the TXT record.
// This prevents DNS poisoning from redirecting badge fetches to a rogue server.
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
