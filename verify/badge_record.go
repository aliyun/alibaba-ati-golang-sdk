package verify

import (
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// BadgeRecordSource indicates where a badge record was resolved from.
type BadgeRecordSource int

const (
	// BadgeRecordSourceATIBadge indicates the record came from _ati-badge.
	BadgeRecordSourceATIBadge BadgeRecordSource = iota
	// BadgeRecordSourceRaBadge indicates the record came from _ra-badge (legacy fallback).
	BadgeRecordSourceRaBadge
)

func (s BadgeRecordSource) String() string {
	switch s {
	case BadgeRecordSourceATIBadge:
		return "ati-badge"
	case BadgeRecordSourceRaBadge:
		return "ra-badge"
	default:
		return fmt.Sprintf("BadgeRecordSource(%d)", int(s))
	}
}

// getValidFormatVersions returns the accepted format version prefixes.
func getValidFormatVersions() []string {
	return []string{"ati-badge1", "ra-badge1"}
}

// ATIBadgeRecord represents a parsed _ati-badge or _ra-badge TXT record.
type ATIBadgeRecord struct {
	// FormatVersion is the format version (e.g., "ati-badge1" or "ra-badge1").
	FormatVersion string
	// Version is the agent version this badge represents (required per PRD 6.5.1).
	Version *models.Version
	// URL is the URL to fetch the badge from the transparency log.
	URL string
	// Source indicates where this record was resolved from.
	Source BadgeRecordSource
}

// ParseATIBadgeRecord parses an _ati-badge TXT record.
// Format: "v=ati-badge1; version=v1.0.0; url=https://..."
// or:     "v=ati-badge1; av=v1.0.0; u=https://..." (shorthand aliases)
// Field aliases: av ↔ version, u ↔ url (consistent with _ati record parsing).
func ParseATIBadgeRecord(txt string) (*ATIBadgeRecord, error) {
	if txt == "" {
		return nil, errors.New("empty TXT record")
	}

	fields := parseSemicolonFields(txt)

	formatVersion := fields["v"]
	if formatVersion == "" {
		return nil, errors.New("missing format version (v=)")
	}

	if !isValidFormatVersion(formatVersion) {
		return nil, fmt.Errorf("unsupported format version: %s", formatVersion)
	}

	// Version resolution order: av > version (consistent with ati_record.go)
	var version *models.Version
	versionStr := fields["av"]
	if versionStr == "" {
		versionStr = fields["version"]
	}
	if versionStr != "" {
		if parsed, err := models.ParseVersion(versionStr); err == nil {
			version = &parsed
		}
	}

	// Version is required for ati-badge1 format (PRD 6.5.1)
	if formatVersion == "ati-badge1" && version == nil {
		return nil, errors.New("missing required field: version (av or version required for ati-badge1)")
	}

	// URL resolution order: u > url (consistent with ati_record.go)
	badgeURL := fields["u"]
	if badgeURL == "" {
		badgeURL = fields["url"]
	}

	if badgeURL == "" {
		return nil, errors.New("missing URL (url= or u=)")
	}

	// Parse and validate URL strictly
	parsed, err := url.Parse(badgeURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Enforce HTTPS scheme only (security requirement)
	if parsed.Scheme != "https" {
		return nil, errors.New("invalid URL: must use https scheme")
	}

	// Require non-empty host
	if parsed.Host == "" {
		return nil, errors.New("invalid URL: missing host")
	}

	// Reject URLs with userinfo (potential credential leak)
	if parsed.User != nil {
		return nil, errors.New("invalid URL: userinfo not allowed")
	}

	// Reject URLs with fragment (not meaningful for badge URLs)
	if parsed.Fragment != "" {
		return nil, errors.New("invalid URL: fragment not allowed")
	}

	return &ATIBadgeRecord{
		FormatVersion: formatVersion,
		Version:       version,
		URL:           badgeURL,
	}, nil
}

// isValidFormatVersion checks if the format version is recognized.
func isValidFormatVersion(v string) bool {
	return slices.Contains(getValidFormatVersions(), v)
}
