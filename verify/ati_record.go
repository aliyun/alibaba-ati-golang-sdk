package verify

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// ATIRecord represents a parsed _ati TXT DNS record.
//
// New format (dual-hostname, one TXT per protocol):
//
//	v=ati1; av=v1.0.0; p=a2a; u=https://platform.example.com/agents/{AgentID}/a2a
//
// Legacy format:
//
//	v=ati1; id={agentId}; ra=aliyun; version=v1.0.0; p=a2a; url=https://...
//
// Field aliases: av ↔ version/ver, u ↔ url, proto ↔ p, mode ↔ m.
type ATIRecord struct {
	ID       string         // Agent ID (explicit id= field, or extracted from URL path)
	RA       string         // Registration Authority identifier (e.g., aliyun)
	Version  models.Version // Semver version
	Mode     ATIRecordMode  // card or direct (default: direct)
	Protocol string         // Protocol filter (mcp/a2a/openapi), empty means wildcard
	URL      string         // Endpoint URL
}

// ATIRecordMode represents the mode field of an _ati TXT record.
type ATIRecordMode int

const (
	ATIRecordModeCard ATIRecordMode = iota
	ATIRecordModeDirect
)

func (m ATIRecordMode) String() string {
	switch m {
	case ATIRecordModeCard:
		return "card"
	case ATIRecordModeDirect:
		return "direct"
	default:
		return "unknown"
	}
}

// ParseATIRecord parses an _ati TXT record string.
// Supports both new format (av, u) and legacy field names (version/ver, url), plus proto as alias for p.
func ParseATIRecord(txt string) (*ATIRecord, error) {
	fields := parseSemicolonFields(txt)

	v, ok := fields["v"]
	if !ok || v != "ati1" {
		return nil, errors.New("missing or invalid version field: expected v=ati1")
	}

	id := fields["id"]
	ra := fields["ra"]

	// Version resolution order: av > version > ver
	versionStr := fields["av"]
	if versionStr == "" {
		versionStr = fields["version"]
	}
	if versionStr == "" {
		versionStr = fields["ver"]
	}
	if versionStr == "" {
		return nil, errors.New("missing required field: av (or version/ver)")
	}
	version, err := models.ParseVersion(versionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: %w", versionStr, err)
	}

	protocol := fields["p"]
	if protocol == "" {
		protocol = fields["proto"]
	}

	// URL resolution order: u > url
	recordURL := fields["u"]
	if recordURL == "" {
		recordURL = fields["url"]
	}

	// Extract agent ID from URL path if not explicitly provided
	if id == "" && recordURL != "" {
		id = extractAgentIDFromURL(recordURL)
	}

	// Mode resolution order: mode > m; default is always direct
	var mode ATIRecordMode
	modeStr := fields["mode"]
	if modeStr == "" {
		modeStr = fields["m"]
	}
	if modeStr != "" {
		switch modeStr {
		case "card":
			mode = ATIRecordModeCard
		case "direct":
			mode = ATIRecordModeDirect
		default:
			return nil, fmt.Errorf("invalid mode %q: must be 'card' or 'direct'", modeStr)
		}
	} else {
		mode = ATIRecordModeDirect
	}

	return &ATIRecord{
		ID:       id,
		RA:       ra,
		Version:  version,
		Mode:     mode,
		Protocol: protocol,
		URL:      recordURL,
	}, nil
}

// FilterATIRecordsByProtocol narrows records to those serving protocol.
//
// A record with an empty Protocol acts as a wildcard and is always kept, since
// older records predate the per-protocol layout. Passing an empty protocol
// disables filtering. Matching is case-insensitive because records in the wild
// spell the protocol both ways (for example "a2a" and "A2A").
//
// This matters because one agent publishes one _ati TXT record per protocol, all
// carrying the same av= version. Version comparison alone therefore cannot pick
// between them.
func FilterATIRecordsByProtocol(records []*ATIRecord, protocol string) []*ATIRecord {
	if protocol == "" {
		return records
	}
	want := strings.ToLower(protocol)
	var out []*ATIRecord
	for _, r := range records {
		if r == nil {
			continue
		}
		if r.Protocol == "" || strings.EqualFold(r.Protocol, want) {
			out = append(out, r)
		}
	}
	return out
}

// extractAgentIDFromURL extracts the agent ID from a URL path containing /agents/{id}/.
// Returns empty string if the pattern is not found.
func extractAgentIDFromURL(rawURL string) string {
	const marker = "/agents/"
	idx := strings.Index(rawURL, marker)
	if idx < 0 {
		return ""
	}
	rest := rawURL[idx+len(marker):]
	// Take everything up to the next slash (or end of string)
	if slashIdx := strings.Index(rest, "/"); slashIdx > 0 {
		return rest[:slashIdx]
	}
	if rest != "" {
		return rest
	}
	return ""
}

// parseSemicolonFields splits "k1=v1; k2=v2; ..." into a map.
func parseSemicolonFields(txt string) map[string]string {
	result := make(map[string]string)
	parts := strings.Split(txt, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		result[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return result
}
