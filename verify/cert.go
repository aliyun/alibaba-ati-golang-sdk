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

// ATIName extracts the ANS name from URI SANs.
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

// Version extracts the version from ATI name in URI SAN.
func (c *CertIdentity) Version() *models.Version {
	name := c.ATIName()
	if name != nil {
		return &name.Version
	}
	return nil
}
