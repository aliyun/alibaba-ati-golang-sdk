package verify

import (
	"errors"
	"fmt"
	"strings"
)

// ATIRecord represents a parsed _ati TXT record for agent discovery.
type ATIRecord struct {
	FormatVersion string
	AgentID       string
	RAEndpoint    string
	Version       string
	Protocol      string
	Mode          string
	URL           string
}

// ParseATIRecord parses an _ati TXT record.
// Format: "v=ati1; id=<agentID>; ra=<endpoint>; ver=<version>; proto=<protocol>; mode=<mode>"
func ParseATIRecord(txt string) (*ATIRecord, error) {
	if txt == "" {
		return nil, errors.New("empty TXT record")
	}

	record := &ATIRecord{}

	for part := range strings.SplitSeq(txt, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if v, found := strings.CutPrefix(part, "v="); found {
			record.FormatVersion = v
		} else if v, found := strings.CutPrefix(part, "id="); found {
			record.AgentID = v
		} else if v, found := strings.CutPrefix(part, "ra="); found {
			record.RAEndpoint = v
		} else if v, found := strings.CutPrefix(part, "ver="); found {
			record.Version = v
		} else if v, found := strings.CutPrefix(part, "proto="); found {
			record.Protocol = v
		} else if v, found := strings.CutPrefix(part, "mode="); found {
			record.Mode = v
		} else if v, found := strings.CutPrefix(part, "url="); found {
			record.URL = v
		}
	}

	if record.FormatVersion == "" {
		return nil, errors.New("missing format version (v=)")
	}

	if record.FormatVersion != "ati1" {
		return nil, fmt.Errorf("unsupported format version: %s", record.FormatVersion)
	}

	return record, nil
}
