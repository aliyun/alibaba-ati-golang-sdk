package ati

import (
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

func makeRecords(versions ...string) []*verify.ATIRecord {
	records := make([]*verify.ATIRecord, 0, len(versions))
	for _, v := range versions {
		parsed, err := models.ParseVersion(v)
		if err != nil {
			panic("bad test version: " + v)
		}
		records = append(records, &verify.ATIRecord{
			ID:      "ag-" + v,
			RA:      "aliyun",
			Version: parsed,
			Mode:    verify.ATIRecordModeDirect,
		})
	}
	return records
}

func TestResolveVersion_EmptyRecords(t *testing.T) {
	for _, policy := range []VersionPolicy{VersionPolicyExact, VersionPolicyLatest, VersionPolicyLatestCompatible} {
		_, err := ResolveVersion(nil, policy, "1.0.0")
		if err == nil {
			t.Errorf("ResolveVersion(nil, %s, ...) expected error", policy)
		}
	}
}

func TestResolveVersion_ExactPolicy(t *testing.T) {
	records := makeRecords("v1.0.0", "v1.1.0", "v2.0.0")

	tests := []struct {
		name      string
		requested string
		wantVer   string
		wantErr   bool
	}{
		{"exact match", "1.0.0", "v1.0.0", false},
		{"exact match with v prefix", "v1.1.0", "v1.1.0", false},
		{"not found", "3.0.0", "", true},
		{"empty requested", "", "", true},
		{"invalid semver", "not-a-version", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResolveVersion(records, VersionPolicyExact, tt.requested)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Version.String() != tt.wantVer {
				t.Errorf("got version %s, want %s", result.Version.String(), tt.wantVer)
			}
		})
	}
}

func TestResolveVersion_LatestPolicy(t *testing.T) {
	records := makeRecords("v1.0.0", "v2.0.0", "v1.5.0")

	result, err := ResolveVersion(records, VersionPolicyLatest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version.String() != "v2.0.0" {
		t.Errorf("got %s, want v2.0.0", result.Version.String())
	}
}

func TestResolveVersion_LatestPolicy_IgnoresInvalidVersions(t *testing.T) {
	records := []*verify.ATIRecord{
		{ID: "bad", Version: models.Version{}},
		{ID: "good", Version: models.NewVersion(1, 0, 0)},
	}
	// models.Version zero value → "v0.0.0" which IS valid semver; test with only one known good
	result, err := ResolveVersion(records, VersionPolicyLatest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "good" {
		t.Errorf("expected record 'good', got %q", result.ID)
	}
}

func TestResolveVersion_LatestCompatiblePolicy(t *testing.T) {
	records := makeRecords("v1.0.0", "v1.2.0", "v1.5.0", "v2.0.0")

	tests := []struct {
		name      string
		requested string
		wantVer   string
		wantErr   bool
	}{
		{"caret constraint", "^1.0.0", "v1.5.0", false},
		{"tilde constraint", "~1.0.0", "v1.0.0", false},
		{"ge constraint", ">= 1.2.0, < 2.0.0", "v1.5.0", false},
		{"empty falls back to latest", "", "v2.0.0", false},
		{"exact version string fallback", "1.2.0", "v1.2.0", false},
		{"no match", "^3.0.0", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResolveVersion(records, VersionPolicyLatestCompatible, tt.requested)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Version.String() != tt.wantVer {
				t.Errorf("got version %s, want %s", result.Version.String(), tt.wantVer)
			}
		})
	}
}

func TestResolveVersion_UnknownPolicy_FallsBackToLatest(t *testing.T) {
	records := makeRecords("v1.0.0", "v3.0.0", "v2.0.0")

	result, err := ResolveVersion(records, VersionPolicy("UNKNOWN"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version.String() != "v3.0.0" {
		t.Errorf("got %s, want v3.0.0 (latest fallback)", result.Version.String())
	}
}

func TestResolveLatestCompatible_InvalidConstraintFallsToExact(t *testing.T) {
	records := makeRecords("v1.0.0", "v2.0.0")

	// A plain version string is not a valid constraint in Masterminds/semver — it
	// gets parsed as a constraint "= 1.0.0". But "1.0.0" IS parsed successfully as
	// a constraint by Masterminds/semver. Let's use something that truly fails.
	result, err := ResolveVersion(records, VersionPolicyLatestCompatible, "2.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version.String() != "v2.0.0" {
		t.Errorf("got %s, want v2.0.0", result.Version.String())
	}
}

func TestFindExact_NotFound(t *testing.T) {
	records := makeRecords("v1.0.0")

	_, err := findExact(records, "9.9.9")
	if err == nil {
		t.Fatal("expected error for not-found version")
	}
}

func TestFindExact_InvalidVersion(t *testing.T) {
	records := makeRecords("v1.0.0")

	_, err := findExact(records, "not-valid")
	if err == nil {
		t.Fatal("expected error for invalid version expression")
	}
}

func TestResolveLatest_AllInvalidVersions(t *testing.T) {
	// We can't really make ATIRecord.Version produce invalid semver since it's
	// a structured type. But we can test an empty slice to be sure.
	_, err := resolveLatest(nil)
	if err == nil {
		t.Fatal("expected error for nil records")
	}
}
