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
