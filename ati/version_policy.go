package ati

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
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
	reqVersion, err := semver.NewVersion(requested)
	if err != nil {
		return nil, fmt.Errorf("invalid requested version %q: %w", requested, err)
	}
	for _, r := range records {
		v, vErr := semver.NewVersion(r.Version.String())
		if vErr != nil {
			continue
		}
		if v.Equal(reqVersion) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("exact version %s not found", requested)
}

func resolveLatest(records []*verify.ATIRecord) (*verify.ATIRecord, error) {
	var best *verify.ATIRecord
	var bestVer *semver.Version
	for _, r := range records {
		v, err := semver.NewVersion(r.Version.String())
		if err != nil {
			continue
		}
		if bestVer == nil || v.GreaterThan(bestVer) {
			best = r
			bestVer = v
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no valid semver records found")
	}
	return best, nil
}

func resolveLatestCompatible(records []*verify.ATIRecord, requested string) (*verify.ATIRecord, error) {
	if requested == "" {
		return resolveLatest(records)
	}

	constraint, err := semver.NewConstraint(requested)
	if err != nil {
		return findExact(records, requested)
	}

	var best *verify.ATIRecord
	var bestVer *semver.Version
	for _, r := range records {
		v, vErr := semver.NewVersion(r.Version.String())
		if vErr != nil {
			continue
		}
		if constraint.Check(v) {
			if bestVer == nil || v.GreaterThan(bestVer) {
				best = r
				bestVer = v
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no records satisfy constraint %q", requested)
	}
	return best, nil
}

func findExact(records []*verify.ATIRecord, requested string) (*verify.ATIRecord, error) {
	reqVer, err := semver.NewVersion(requested)
	if err != nil {
		return nil, fmt.Errorf("invalid version expression %q: %w", requested, err)
	}
	for _, r := range records {
		v, vErr := semver.NewVersion(r.Version.String())
		if vErr != nil {
			continue
		}
		if v.Equal(reqVer) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("exact version %s not found", requested)
}
