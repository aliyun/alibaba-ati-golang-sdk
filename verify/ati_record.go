package verify

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// ATIRecord represents a parsed _ati TXT DNS record.
// Format: v=ati1; id={agentId}; ra=aliyun; version=v1.0.0; p=a2a; url=https://...
// Also accepts: ver= (alias for version=), proto= (alias for p=)
type ATIRecord struct {
	ID       string         // Agent ID (e.g., d6c78fcb-...)
	RA       string         // Registration Authority identifier (e.g., aliyun)
	Version  models.Version // Semver version
	Mode     ATIRecordMode  // card or direct (inferred from url presence if not set)
	Protocol string         // Protocol filter (mcp/a2a/openapi), empty means wildcard
	URL      string         // Metadata endpoint URL
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
// Supports both canonical field names (version, p) and aliases (ver, proto).
func ParseATIRecord(txt string) (*ATIRecord, error) {
	fields := parseSemicolonFields(txt)

	v, ok := fields["v"]
	if !ok || v != "ati1" {
		return nil, errors.New("missing or invalid version field: expected v=ati1")
	}

	id := fields["id"]
	ra := fields["ra"]

	versionStr := fields["version"]
	if versionStr == "" {
		versionStr = fields["ver"]
	}
	if versionStr == "" {
		return nil, errors.New("missing required field: version (or ver)")
	}
	version, err := models.ParseVersion(versionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: %w", versionStr, err)
	}

	protocol := fields["p"]
	if protocol == "" {
		protocol = fields["proto"]
	}

	url := fields["url"]

	var mode ATIRecordMode
	if modeStr, ok := fields["mode"]; ok {
		switch modeStr {
		case "card":
			mode = ATIRecordModeCard
		case "direct":
			mode = ATIRecordModeDirect
		default:
			return nil, fmt.Errorf("invalid mode %q: must be 'card' or 'direct'", modeStr)
		}
	} else if url != "" {
		mode = ATIRecordModeCard
	} else {
		mode = ATIRecordModeDirect
	}

	return &ATIRecord{
		ID:       id,
		RA:       ra,
		Version:  version,
		Mode:     mode,
		Protocol: protocol,
		URL:      url,
	}, nil
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
