package ati

import (
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

func rec(ver, proto, url string) *verify.ATIRecord {
	v, _ := models.ParseVersion(ver)
	return &verify.ATIRecord{Version: v, Protocol: proto, URL: url}
}

// One agent publishes one record per protocol, all at the same version — the
// layout PRD section 4.3 prescribes. Version comparison cannot separate them.
func TestResolveVersionForProtocol(t *testing.T) {
	records := []*verify.ATIRecord{
		rec("v1.0.0", "a2a", "https://p.example.com/agents/x/a2a"),
		rec("v1.0.0", "mcp", "https://p.example.com/agents/x/mcp"),
	}

	for _, tc := range []struct{ proto, wantURL string }{
		{"a2a", "https://p.example.com/agents/x/a2a"},
		{"mcp", "https://p.example.com/agents/x/mcp"},
		{"A2A", "https://p.example.com/agents/x/a2a"}, // case-insensitive
	} {
		got, err := ResolveVersionForProtocol(records, VersionPolicyLatest, "", tc.proto)
		if err != nil {
			t.Errorf("protocol %q: %v", tc.proto, err)
			continue
		}
		if got.URL != tc.wantURL {
			t.Errorf("protocol %q: got %s, want %s", tc.proto, got.URL, tc.wantURL)
		}
	}

	if _, err := ResolveVersionForProtocol(records, VersionPolicyLatest, "", "openapi"); err == nil {
		t.Error("unknown protocol should error, got nil")
	}
}

// Without a protocol the pick must still be stable regardless of the order the
// resolver hands the records back in.
func TestResolveVersionDeterministicOnTie(t *testing.T) {
	a := rec("v1.0.0", "a2a", "https://p.example.com/agents/x/a2a")
	m := rec("v1.0.0", "mcp", "https://p.example.com/agents/x/mcp")

	first, err := ResolveVersion([]*verify.ATIRecord{a, m}, VersionPolicyLatest, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveVersion([]*verify.ATIRecord{m, a}, VersionPolicyLatest, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.URL != second.URL {
		t.Errorf("order-dependent result: %s vs %s", first.URL, second.URL)
	}
}

// A record with no protocol predates the per-protocol layout and must stay
// usable for any requested protocol.
func TestFilterKeepsWildcardRecord(t *testing.T) {
	records := []*verify.ATIRecord{rec("v1.0.0", "", "https://p.example.com/legacy")}
	got, err := ResolveVersionForProtocol(records, VersionPolicyLatest, "", "mcp")
	if err != nil {
		t.Fatalf("wildcard record should match any protocol: %v", err)
	}
	if got.URL != "https://p.example.com/legacy" {
		t.Errorf("got %s", got.URL)
	}
}
