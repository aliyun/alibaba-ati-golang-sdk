// Package verify provides ATI trust verification functionality.
package verify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// CertValidityCheck examines a peer certificate's validity period.
type CertValidityCheck struct {
	Valid            bool
	RemainingPercent float64
	ExpiresAt        time.Time
	Warning          string
}

// CheckCertValidity validates a peer certificate's time bounds and computes remaining lifetime.
func CheckCertValidity(cert *x509.Certificate, now time.Time) *CertValidityCheck {
	result := &CertValidityCheck{
		ExpiresAt: cert.NotAfter,
	}

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		result.Valid = false
		if now.After(cert.NotAfter) {
			result.Warning = "certificate has expired"
		} else {
			result.Warning = "certificate is not yet valid"
		}
		return result
	}

	result.Valid = true
	total := cert.NotAfter.Sub(cert.NotBefore).Seconds()
	remaining := cert.NotAfter.Sub(now).Seconds()
	if total > 0 {
		result.RemainingPercent = remaining / total
	}

	if result.RemainingPercent < 0.2 {
		daysLeft := int(remaining / 86400)
		result.Warning = fmt.Sprintf("certificate expires in %d days (%.0f%% lifetime remaining)", daysLeft, result.RemainingPercent*100)
	}

	return result
}

// CertFingerprint represents a SHA-256 certificate fingerprint.
type CertFingerprint struct {
	bytes [32]byte
}

// CertFingerprintFromDER computes the fingerprint from DER-encoded certificate bytes.
func CertFingerprintFromDER(der []byte) CertFingerprint {
	return CertFingerprint{bytes: sha256.Sum256(der)}
}

// CertFingerprintFromBytes creates a fingerprint from raw bytes.
func CertFingerprintFromBytes(b [32]byte) CertFingerprint {
	return CertFingerprint{bytes: b}
}

// ParseCertFingerprint parses a fingerprint from "SHA256:<hex>" format.
func ParseCertFingerprint(s string) (CertFingerprint, error) {
	// Handle SHA256:, sha256:, SHA-256:, sha-256: prefixes
	var hexStr string
	switch {
	case strings.HasPrefix(s, "SHA256:"):
		hexStr = s[7:]
	case strings.HasPrefix(s, "sha256:"):
		hexStr = s[7:]
	case strings.HasPrefix(s, "SHA-256:"):
		hexStr = s[8:]
	case strings.HasPrefix(s, "sha-256:"):
		hexStr = s[8:]
	default:
		return CertFingerprint{}, errors.New("invalid fingerprint format: must start with 'SHA256:' or 'SHA-256:' (e.g., SHA256:abc123...)")
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return CertFingerprint{}, fmt.Errorf("invalid fingerprint hex: %w", err)
	}

	const sha256Len = 32
	if len(decoded) != sha256Len {
		return CertFingerprint{}, fmt.Errorf("invalid fingerprint length: expected 32 bytes, got %d", len(decoded))
	}

	var fp CertFingerprint
	copy(fp.bytes[:], decoded)
	return fp, nil
}

// String returns the fingerprint as "SHA256:<hex>".
func (f CertFingerprint) String() string {
	return "SHA256:" + hex.EncodeToString(f.bytes[:])
}

// Bytes returns the raw fingerprint bytes.
func (f CertFingerprint) Bytes() [32]byte {
	return f.bytes
}

// ToHex returns the hex string without prefix.
func (f CertFingerprint) ToHex() string {
	return hex.EncodeToString(f.bytes[:])
}

// Matches checks if this fingerprint matches a string representation.
func (f CertFingerprint) Matches(other string) bool {
	parsed, err := ParseCertFingerprint(other)
	if err != nil {
		return false
	}
	return f.bytes == parsed.bytes
}

// MatchesAny reports whether this fingerprint matches any of the given
// string representations, skipping empty candidates. Used to accept either
// a TL record's current or its previous (pre-renewal) fingerprint.
func (f CertFingerprint) MatchesAny(candidates ...string) bool {
	for _, c := range candidates {
		if c != "" && f.Matches(c) {
			return true
		}
	}
	return false
}

// Equal returns true if the fingerprints are equal.
func (f CertFingerprint) Equal(other CertFingerprint) bool {
	return f.bytes == other.bytes
}

// IsZero returns true if the fingerprint has not been set.
func (f CertFingerprint) IsZero() bool {
	return f.bytes == [32]byte{}
}

// ATIName represents an ANS name URI (e.g., ati://v1.0.0.agent.example.com).
type ATIName struct {
	Version models.Version
	Host    string
	raw     string
}

// ParseATIName parses an ANS name from a URI string.
// Format: ati://v<major>.<minor>.<patch>.<fqdn>
func ParseATIName(uri string) (*ATIName, error) {
	const prefix = "ati://"

	if uri == "" {
		return nil, errors.New("empty ATI name")
	}

	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("ATI name must start with '%s': %s", prefix, uri)
	}

	rest := uri[len(prefix):]

	// The format is: v<major>.<minor>.<patch>.<fqdn>
	if !strings.HasPrefix(rest, "v") {
		return nil, fmt.Errorf("ATI name version must start with 'v': %s", uri)
	}

	const minATINameParts = 4 // v<major>.<minor>.<patch>.<fqdn>
	parts := strings.SplitN(rest, ".", minATINameParts)
	if len(parts) < minATINameParts {
		return nil, fmt.Errorf("ATI name must have version and FQDN: %s", uri)
	}

	// Parse version from first 3 parts (including the 'v' prefix)
	versionStr := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	version, err := models.ParseVersion(versionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version in ATI name: %w", err)
	}

	return &ATIName{
		Version: version,
		Host:    strings.ToLower(parts[3]),
		raw:     uri,
	}, nil
}

// String returns the raw ATI name URI.
func (a *ATIName) String() string {
	return a.raw
}

// CertIdentity holds the relevant identity information extracted from an X.509 certificate.
type CertIdentity struct {
	// CommonName from the certificate subject.
	CommonName *string
	// DNSSANs are the DNS Subject Alternative Names.
	DNSSANs []string
	// URISANs are the URI Subject Alternative Names.
	URISANs []string
	// Fingerprint is the certificate's SHA-256 fingerprint (full cert DER).
	Fingerprint CertFingerprint
	// SPKIFingerprint is the SHA-256 of the SubjectPublicKeyInfo (DER).
	SPKIFingerprint CertFingerprint
}

// NewCertIdentity creates a new CertIdentity from components.
func NewCertIdentity(commonName *string, dnsSANs, uriSANs []string, fingerprint CertFingerprint) *CertIdentity {
	return &CertIdentity{
		CommonName:  commonName,
		DNSSANs:     dnsSANs,
		URISANs:     uriSANs,
		Fingerprint: fingerprint,
	}
}

// CertIdentityFromX509 extracts identity from an x509.Certificate.
func CertIdentityFromX509(cert *x509.Certificate) *CertIdentity {
	var cn *string
	if cert.Subject.CommonName != "" {
		cn = &cert.Subject.CommonName
	}

	// Extract URI SANs
	uriSANs := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uriSANs = append(uriSANs, uri.String())
	}

	fp := CertFingerprintFromDER(cert.Raw)
	spkiFP := CertFingerprint{bytes: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}

	return &CertIdentity{
		CommonName:      cn,
		DNSSANs:         cert.DNSNames,
		URISANs:         uriSANs,
		Fingerprint:     fp,
		SPKIFingerprint: spkiFP,
	}
}

// CertIdentityFromDER parses a DER-encoded certificate and extracts identity.
func CertIdentityFromDER(der []byte) (*CertIdentity, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return CertIdentityFromX509(cert), nil
}

// CertIdentityFromPEM parses a PEM-encoded certificate and extracts identity.
// Accepts both raw PEM and URL-encoded PEM (as forwarded by Nginx via $ssl_client_escaped_cert).
func CertIdentityFromPEM(pemData string) (*CertIdentity, error) {
	// Try the input as-is first. Raw PEM's base64 body commonly contains '+',
	// which url.QueryUnescape would otherwise misinterpret as a space and
	// corrupt; unconditionally unescaping first broke that common case. Only
	// fall back to QueryUnescape (for the documented Nginx-forwarded form,
	// which won't parse as PEM directly) when the raw input isn't valid PEM.
	if block, _ := pem.Decode([]byte(pemData)); block != nil {
		if ident, err := CertIdentityFromDER(block.Bytes); err == nil {
			return ident, nil
		}
	}

	decoded, err := url.QueryUnescape(pemData)
	if err != nil {
		decoded = pemData
	}
	block, _ := pem.Decode([]byte(decoded))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return CertIdentityFromDER(block.Bytes)
}

// CertIdentityFromFingerprintAndCN creates a CertIdentity with just fingerprint and CN.
func CertIdentityFromFingerprintAndCN(fingerprint CertFingerprint, cn string) *CertIdentity {
	return &CertIdentity{
		CommonName:  &cn,
		DNSSANs:     []string{cn},
		URISANs:     nil,
		Fingerprint: fingerprint,
	}
}

// FQDN returns the FQDN from the certificate.
// Prefers DNS SAN (more reliable) over CN.
func (c *CertIdentity) FQDN() *string {
	if len(c.DNSSANs) > 0 {
		return &c.DNSSANs[0]
	}
	return c.CommonName
}

// CoversHost reports whether any DNS SAN in the certificate covers host.
//
// Wildcard SANs are honoured because the access certificate in the dual-hostname
// model may be a platform-wide wildcard shared by many agents, so an exact
// comparison against a single SAN is not sufficient.
func (c *CertIdentity) CoversHost(host string) bool {
	for _, san := range c.DNSSANs {
		if matchesDNSName(san, host) {
			return true
		}
	}
	return false
}

// matchesDNSName reports whether host matches a certificate DNS SAN pattern.
//
// A leading "*." matches exactly one label (RFC 6125 section 6.4.3), so
// "*.example.com" matches "a.example.com" but neither "example.com" nor
// "a.b.example.com". The wildcard is only recognised as the entire leftmost
// label; patterns such as "f*.example.com" are treated literally. Comparison is
// case-insensitive and a trailing dot on either side is ignored.
func matchesDNSName(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == "" || host == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}

// ATIName extracts the first valid ANS name from URI SANs.
// Use ATINames() to retrieve all ati:// identities (e.g. dual-hostname certs).
func (c *CertIdentity) ATIName() *ATIName {
	for _, uri := range c.URISANs {
		if strings.HasPrefix(uri, "ati://") {
			if name, err := ParseATIName(uri); err == nil {
				return name
			}
		}
	}
	return nil
}

// ATINames extracts all valid ATI names from URI SANs.
// A certificate may carry multiple ati:// URIs (e.g. one per hostname in a
// dual-hostname model). Returns nil when no valid ati:// URI SAN is present.
func (c *CertIdentity) ATINames() []*ATIName {
	var names []*ATIName
	for _, uri := range c.URISANs {
		if strings.HasPrefix(uri, "ati://") {
			if name, err := ParseATIName(uri); err == nil {
				names = append(names, name)
			}
		}
	}
	return names
}

// ATINameForHost returns the ATI name whose host matches the given FQDN,
// or the first valid ATI name as fallback.
func (c *CertIdentity) ATINameForHost(host string) *ATIName {
	host = strings.ToLower(host)
	var first *ATIName
	for _, uri := range c.URISANs {
		if strings.HasPrefix(uri, "ati://") {
			if name, err := ParseATIName(uri); err == nil {
				if first == nil {
					first = name
				}
				if name.Host == host {
					return name
				}
			}
		}
	}
	return first
}

// Version extracts the version from ATI name in URI SAN.
func (c *CertIdentity) Version() *models.Version {
	name := c.ATIName()
	if name != nil {
		return &name.Version
	}
	return nil
}
