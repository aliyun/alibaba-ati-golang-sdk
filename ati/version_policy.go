package ati

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// VersionPolicy controls version resolution strategy.
type VersionPolicy string

const (
	VersionPolicyExact            VersionPolicy = "EXACT"
	VersionPolicyLatest           VersionPolicy = "LATEST"
	VersionPolicyLatestCompatible VersionPolicy = "LATEST_COMPATIBLE"
)

// ResolveVersion selects the appropriate version from available ATI records
// based on the version policy and requested version range.
func ResolveVersion(records []*verify.ATIRecord, policy VersionPolicy, requested string) (*verify.ATIRecord, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no ATI records available")
	}

	switch policy {
	case VersionPolicyExact:
		return resolveExact(records, requested)
	case VersionPolicyLatest:
		return resolveLatest(records)
	case VersionPolicyLatestCompatible:
		return resolveLatestCompatible(records, requested)
	default:
		return resolveLatest(records)
	}
}

func resolveExact(records []*verify.ATIRecord, requested string) (*verify.ATIRecord, error) {
	if requested == "" {
		return nil, fmt.Errorf("EXACT policy requires a version")
	}
	reqVersion, err := models.ParseVersion(requested)
	if err != nil {
		return nil, fmt.Errorf("invalid requested version %q: %w", requested, err)
	}
	for _, r := range records {
		if r.Version.Compare(reqVersion) == 0 {
			return r, nil
		}
	}
	return nil, fmt.Errorf("exact version %s not found", requested)
}

func resolveLatest(records []*verify.ATIRecord) (*verify.ATIRecord, error) {
	var best *verify.ATIRecord
	for _, r := range records {
		if best == nil || r.Version.Compare(best.Version) > 0 {
			best = r
		}
	}
	return best, nil
}

func resolveLatestCompatible(records []*verify.ATIRecord, requested string) (*verify.ATIRecord, error) {
	if requested == "" {
		return resolveLatest(records)
	}

	// Parse semver range: "^1.2.0" means >=1.2.0 <2.0.0
	major, err := parseMajorFromRange(requested)
	if err != nil {
		return resolveLatest(records)
	}

	var best *verify.ATIRecord
	for _, r := range records {
		parts := strings.Split(r.Version.String(), ".")
		if len(parts) < 1 {
			continue
		}
		vStr := strings.TrimPrefix(parts[0], "v")
		recordMajor, parseErr := strconv.Atoi(vStr)
		if parseErr != nil {
			continue
		}
		if recordMajor == major {
			if best == nil || r.Version.Compare(best.Version) > 0 {
				best = r
			}
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no compatible version found for major %d", major)
	}
	return best, nil
}

func parseMajorFromRange(rangeStr string) (int, error) {
	s := strings.TrimPrefix(rangeStr, "^")
	s = strings.TrimPrefix(s, "~")
	s = strings.TrimPrefix(s, ">=")
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) == 0 {
		return 0, fmt.Errorf("invalid range: %s", rangeStr)
	}
	return strconv.Atoi(parts[0])
}
