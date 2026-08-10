package verify

import (
	"fmt"
	"net/url"
	"strings"
)

// RewriteBadgeURLHost replaces the host in a badge URL with the trusted TL host.
// If trustedHost already includes a port, it is used as-is; otherwise the
// original port from the URL is preserved.
func RewriteBadgeURLHost(rawURL, trustedHost string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid badge URL: %w", err)
	}
	if strings.Contains(trustedHost, ":") {
		parsed.Host = trustedHost
	} else {
		origPort := parsed.Port()
		if origPort != "" {
			parsed.Host = trustedHost + ":" + origPort
		} else {
			parsed.Host = trustedHost
		}
	}
	return parsed.String(), nil
}
