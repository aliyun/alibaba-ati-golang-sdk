package models

import (
	"errors"
	"fmt"
	"strings"
)

// maxLabelLength is the maximum length of a DNS label per RFC 1035.
const maxLabelLength = 63

// Fqdn represents a validated Fully Qualified Domain Name.
type Fqdn struct {
	value string
}

// NewFqdn creates a new Fqdn from a string, validating the format.
func NewFqdn(domain string) (Fqdn, error) {
	if domain == "" {
		return Fqdn{}, errors.New("empty domain")
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Validate each label
	for label := range strings.SplitSeq(domain, ".") {
		if label == "" {
			return Fqdn{}, errors.New("empty label")
		}
		if len(label) > maxLabelLength {
			return Fqdn{}, errors.New("label too long")
		}
		for _, c := range label {
			if !isValidLabelChar(c) {
				return Fqdn{}, fmt.Errorf("invalid character in label: %s", label)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return Fqdn{}, errors.New("label cannot start or end with hyphen")
		}
	}

	return Fqdn{value: strings.ToLower(domain)}, nil
}

// isValidLabelChar returns true if the character is valid in a DNS label.
func isValidLabelChar(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-'
}

// String returns the string representation of the FQDN.
func (f Fqdn) String() string {
	return f.value
}

// ATIBadgeName returns the _ati-badge subdomain for this FQDN.
func (f Fqdn) ATIBadgeName() string {
	return "_ati-badge." + f.value
}

// RaBadgeName returns the _ra-badge subdomain for this FQDN (legacy fallback).
func (f Fqdn) RaBadgeName() string {
	return "_ra-badge." + f.value
}

// TlsaName returns the TLSA record name for this FQDN and port.
func (f Fqdn) TlsaName(port uint16) string {
	return fmt.Sprintf("_%d._tcp.%s", port, f.value)
}

// ATIDiscoveryName returns the _ati subdomain for DNS discovery.
func (f Fqdn) ATIDiscoveryName() string {
	return "_ati." + f.value
}

// IdentityTLSAName returns the TLSA record name for identity certificate verification.
func (f Fqdn) IdentityTLSAName() string {
	return "_ati-identity._tls." + f.value
}

// IsZero returns true if the Fqdn has not been set.
func (f Fqdn) IsZero() bool {
	return f.value == ""
}
