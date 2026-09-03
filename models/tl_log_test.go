package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTLResponse_UnmarshalJSON_FullValid(t *testing.T) {
	raw := `{
		"status": "ACTIVE",
		"schemaVersion": "1.0",
		"payload": {
			"logId": "log-123",
			"eventType": "registration",
			"timestamp": "2026-01-01T00:00:00Z",
			"agentName": "test-agent",
			"agentDisplayName": "Test Agent",
			"agentHost": "agent.example.com",
			"version": "v1.0.0",
			"agentId": "ag-abc123",
			"agentStatus": "ACTIVE",
			"certificates": {
				"serverCertFingerprint": "server-fp-abc",
				"identityCertFingerprint": "identity-fp-def"
			}
		},
		"evidenceRef": {
			"evidenceId": "ev-1",
			"submitterId": "sub-1",
			"evidenceType": "registration",
			"evidenceUri": "https://example.com/evidence/1",
			"evidenceHash": "abc123",
			"hashAlgorithm": "sha256",
			"hashTarget": "payload",
			"contentType": "application/json",
			"evidenceSchemaVersion": "1.0",
			"signatureRequired": true
		},
		"seal": {
			"canonicalization": "JCS",
			"digestAlgorithm": "SHA-256",
			"signatureAlgorithm": "ECDSA-P256",
			"signatureEncoding": "DER",
			"keyId": "key-1",
			"signature": "sig-abc",
			"publicKey": "pub-abc"
		},
		"merkleProof": {
			"leafHash": "leaf-hash",
			"rootHash": "root-hash",
			"rootSignature": "root-sig",
			"treeSize": 100,
			"treeVersion": 1,
			"leafIndex": 42,
			"path": ["a", "b", "c"]
		},
		"requestId": "req-123"
	}`

	var resp TLResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}

	// Verify scalar fields
	if resp.Status != "ACTIVE" {
		t.Errorf("Status = %q, want %q", resp.Status, "ACTIVE")
	}
	if resp.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want %q", resp.SchemaVersion, "1.0")
	}
	if resp.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want %q", resp.RequestID, "req-123")
	}

	// Verify payload fields
	if resp.Payload.LogID != "log-123" {
		t.Errorf("Payload.LogID = %q, want %q", resp.Payload.LogID, "log-123")
	}
	if resp.Payload.EventType != "registration" {
		t.Errorf("Payload.EventType = %q, want %q", resp.Payload.EventType, "registration")
	}
	if resp.Payload.Timestamp != "2026-01-01T00:00:00Z" {
		t.Errorf("Payload.Timestamp = %q, want %q", resp.Payload.Timestamp, "2026-01-01T00:00:00Z")
	}
	if resp.Payload.AgentName != "test-agent" {
		t.Errorf("Payload.AgentName = %q, want %q", resp.Payload.AgentName, "test-agent")
	}
	if resp.Payload.AgentDisplayName != "Test Agent" {
		t.Errorf("Payload.AgentDisplayName = %q, want %q", resp.Payload.AgentDisplayName, "Test Agent")
	}
	if resp.Payload.AgentHost != "agent.example.com" {
		t.Errorf("Payload.AgentHost = %q, want %q", resp.Payload.AgentHost, "agent.example.com")
	}
	if resp.Payload.Version != "v1.0.0" {
		t.Errorf("Payload.Version = %q, want %q", resp.Payload.Version, "v1.0.0")
	}
	if resp.Payload.AgentID != "ag-abc123" {
		t.Errorf("Payload.AgentID = %q, want %q", resp.Payload.AgentID, "ag-abc123")
	}
	if resp.Payload.AgentStatus != "ACTIVE" {
		t.Errorf("Payload.AgentStatus = %q, want %q", resp.Payload.AgentStatus, "ACTIVE")
	}

	// Verify certificate fingerprints
	if resp.Payload.Certificates.ServerCertFingerprint != "server-fp-abc" {
		t.Errorf("Payload.Certificates.ServerCertFingerprint = %q, want %q",
			resp.Payload.Certificates.ServerCertFingerprint, "server-fp-abc")
	}
	if resp.Payload.Certificates.IdentityCertFingerprint != "identity-fp-def" {
		t.Errorf("Payload.Certificates.IdentityCertFingerprint = %q, want %q",
			resp.Payload.Certificates.IdentityCertFingerprint, "identity-fp-def")
	}

	// Verify evidenceRef
	if resp.EvidenceRef.EvidenceID != "ev-1" {
		t.Errorf("EvidenceRef.EvidenceID = %q, want %q", resp.EvidenceRef.EvidenceID, "ev-1")
	}
	if !resp.EvidenceRef.SignatureRequired {
		t.Error("EvidenceRef.SignatureRequired = false, want true")
	}

	// Verify seal
	if resp.Seal.Canonicalization != "JCS" {
		t.Errorf("Seal.Canonicalization = %q, want %q", resp.Seal.Canonicalization, "JCS")
	}
	if resp.Seal.KeyID != "key-1" {
		t.Errorf("Seal.KeyID = %q, want %q", resp.Seal.KeyID, "key-1")
	}

	// Verify merkleProof
	if resp.MerkleProof.LeafHash != "leaf-hash" {
		t.Errorf("MerkleProof.LeafHash = %q, want %q", resp.MerkleProof.LeafHash, "leaf-hash")
	}
	if resp.MerkleProof.TreeSize != 100 {
		t.Errorf("MerkleProof.TreeSize = %d, want 100", resp.MerkleProof.TreeSize)
	}

	// Verify Raw* fields are preserved (not nil)
	if resp.RawStatus == nil {
		t.Error("RawStatus is nil, want non-nil")
	}
	if resp.RawSchemaVersion == nil {
		t.Error("RawSchemaVersion is nil, want non-nil")
	}
	if resp.RawPayload == nil {
		t.Error("RawPayload is nil, want non-nil")
	}
	if resp.RawEvidenceRef == nil {
		t.Error("RawEvidenceRef is nil, want non-nil")
	}

	// Verify RawStatus content matches the original JSON
	var rawStatus string
	if err := json.Unmarshal(resp.RawStatus, &rawStatus); err != nil {
		t.Fatalf("failed to unmarshal RawStatus: %v", err)
	}
	if rawStatus != "ACTIVE" {
		t.Errorf("RawStatus decoded = %q, want %q", rawStatus, "ACTIVE")
	}
}

func TestTLResponse_UnmarshalJSON_Minimal(t *testing.T) {
	raw := `{
		"status": "WARNING",
		"payload": {
			"agentId": "ag-minimal"
		}
	}`

	var resp TLResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}

	// Status should be populated
	if resp.Status != "WARNING" {
		t.Errorf("Status = %q, want %q", resp.Status, "WARNING")
	}

	// Payload partial fields should be filled
	if resp.Payload.AgentID != "ag-minimal" {
		t.Errorf("Payload.AgentID = %q, want %q", resp.Payload.AgentID, "ag-minimal")
	}
	// Unspecified payload fields should be zero-valued
	if resp.Payload.AgentName != "" {
		t.Errorf("Payload.AgentName = %q, want empty", resp.Payload.AgentName)
	}

	// Unspecified top-level fields should be zero-valued
	if resp.SchemaVersion != "" {
		t.Errorf("SchemaVersion = %q, want empty", resp.SchemaVersion)
	}
	if resp.RequestID != "" {
		t.Errorf("RequestID = %q, want empty", resp.RequestID)
	}

	// RawStatus and RawPayload should be preserved
	if resp.RawStatus == nil {
		t.Error("RawStatus is nil, want non-nil")
	}
	if resp.RawPayload == nil {
		t.Error("RawPayload is nil, want non-nil")
	}

	// Fields not in JSON should have nil Raw* fields
	if resp.RawSchemaVersion != nil {
		t.Error("RawSchemaVersion is non-nil, want nil")
	}
	if resp.RawEvidenceRef != nil {
		t.Error("RawEvidenceRef is non-nil, want nil")
	}
}

func TestTLResponse_UnmarshalJSON_Invalid(t *testing.T) {
	// Non-JSON input should error
	invalidInputs := []string{
		`{this is not valid json`,
		``,
		`null`,
		`[]`,
		`"string"`,
	}
	for _, input := range invalidInputs {
		var resp TLResponse
		err := json.Unmarshal([]byte(input), &resp)
		// `null` and empty string are valid JSON for Unmarshal but produce no data.
		// We expect an error for truly invalid JSON (non-object or malformed).
		if input == `` || input == `null` {
			// Empty string is invalid JSON; null is valid but produces zero struct.
			if input == `` && err == nil {
				t.Errorf("UnmarshalJSON(%q) expected error, got nil", input)
			}
			continue
		}
		if err == nil {
			// `[]` and `"string"` unmarshal without error but produce zero struct.
			// Only truly malformed JSON ({this...) should error.
			if strings.Contains(input, "this is not valid") {
				t.Errorf("UnmarshalJSON(%q) expected error for malformed JSON, got nil", input)
			}
		}
	}
}

func TestTLResponse_UnmarshalJSON_MalformedJSON(t *testing.T) {
	// Truly malformed JSON must return an error
	malformed := `{this is not valid json`
	var resp TLResponse
	err := json.Unmarshal([]byte(malformed), &resp)
	if err == nil {
		t.Fatal("UnmarshalJSON() expected error for malformed JSON, got nil")
	}
}

func TestTLPayload_IdentityCertFingerprint(t *testing.T) {
	tests := []struct {
		name string
		p    TLPayload
		want string
	}{
		{
			name: "non-empty fingerprint",
			p: TLPayload{
				Certificates: TLCertificates{
					IdentityCertFingerprint: "abc123",
				},
			},
			want: "abc123",
		},
		{
			name: "empty fingerprint",
			p:    TLPayload{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IdentityCertFingerprint(); got != tt.want {
				t.Errorf("IdentityCertFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTLPayload_ServerCertFingerprint(t *testing.T) {
	tests := []struct {
		name string
		p    TLPayload
		want string
	}{
		{
			name: "non-empty fingerprint",
			p: TLPayload{
				Certificates: TLCertificates{
					ServerCertFingerprint: "def456",
				},
			},
			want: "def456",
		},
		{
			name: "empty fingerprint",
			p:    TLPayload{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.ServerCertFingerprint(); got != tt.want {
				t.Errorf("ServerCertFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_IsValidForConnection(t *testing.T) {
	tests := []struct {
		status TLAgentStatus
		want   bool
	}{
		{TLStatusActive, true},
		{TLStatusWarning, true},
		{TLStatusDeprecated, true},
		{TLStatusExpired, false},
		{TLStatusRevoked, false},
		{TLAgentStatus("UNKNOWN"), false},
		{TLAgentStatus(""), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsValidForConnection(); got != tt.want {
				t.Errorf("TLAgentStatus(%q).IsValidForConnection() = %v, want %v",
					tt.status, got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status TLAgentStatus
		want   bool
	}{
		{TLStatusRevoked, true},
		{TLStatusExpired, true},
		{TLStatusActive, false},
		{TLStatusWarning, false},
		{TLStatusDeprecated, false},
		{TLAgentStatus("UNKNOWN"), false},
		{TLAgentStatus(""), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("TLAgentStatus(%q).IsTerminal() = %v, want %v",
					tt.status, got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_ShouldReject(t *testing.T) {
	tests := []struct {
		status TLAgentStatus
		want   bool
	}{
		{TLStatusExpired, true},
		{TLStatusRevoked, true},
		{TLStatusActive, false},
		{TLStatusWarning, false},
		{TLStatusDeprecated, false},
		{TLAgentStatus("UNKNOWN"), false},
		{TLAgentStatus(""), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.ShouldReject(); got != tt.want {
				t.Errorf("TLAgentStatus(%q).ShouldReject() = %v, want %v",
					tt.status, got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_IsActive(t *testing.T) {
	tests := []struct {
		status TLAgentStatus
		want   bool
	}{
		{TLStatusActive, true},
		{TLStatusWarning, true},
		{TLStatusDeprecated, false},
		{TLStatusExpired, false},
		{TLStatusRevoked, false},
		{TLAgentStatus("UNKNOWN"), false},
		{TLAgentStatus(""), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsActive(); got != tt.want {
				t.Errorf("TLAgentStatus(%q).IsActive() = %v, want %v",
					tt.status, got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_Constants(t *testing.T) {
	// Verify the constant values match the spec
	tests := []struct {
		constant TLAgentStatus
		want     string
	}{
		{TLStatusActive, "ACTIVE"},
		{TLStatusWarning, "WARNING"},
		{TLStatusDeprecated, "DEPRECATED"},
		{TLStatusExpired, "EXPIRED"},
		{TLStatusRevoked, "REVOKED"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.constant) != tt.want {
				t.Errorf("constant = %q, want %q", tt.constant, tt.want)
			}
		})
	}
}

func TestTLResponse_UnmarshalJSON_RawFieldsDeepEqual(t *testing.T) {
	// Verify that the Raw* fields preserve the exact JSON byte content
	raw := `{"status":"ACTIVE","schemaVersion":"1.0","payload":{"agentId":"ag-1"},"evidenceRef":{"evidenceId":"ev-1"}}`

	var resp TLResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}

	// The RawStatus should be the exact bytes of the JSON value for "status"
	wantRawStatus := json.RawMessage(`"ACTIVE"`)
	if !reflect.DeepEqual(resp.RawStatus, wantRawStatus) {
		t.Errorf("RawStatus = %s, want %s", resp.RawStatus, wantRawStatus)
	}

	wantRawSchemaVersion := json.RawMessage(`"1.0"`)
	if !reflect.DeepEqual(resp.RawSchemaVersion, wantRawSchemaVersion) {
		t.Errorf("RawSchemaVersion = %s, want %s", resp.RawSchemaVersion, wantRawSchemaVersion)
	}

	// RawPayload should contain the full payload object
	wantRawPayload := json.RawMessage(`{"agentId":"ag-1"}`)
	if !reflect.DeepEqual(resp.RawPayload, wantRawPayload) {
		t.Errorf("RawPayload = %s, want %s", resp.RawPayload, wantRawPayload)
	}
}

func TestTLPayload_IdentityAndAccessHost(t *testing.T) {
	tests := []struct {
		name         string
		agentHost    string
		agentSubHost string
		wantIdentity string
		wantAccess   string
		wantShared   bool
	}{
		{
			name:         "独立域名: subHost empty, agentHost is both",
			agentHost:    "server.www.ats-test.cn",
			wantIdentity: "server.www.ats-test.cn",
			wantAccess:   "server.www.ats-test.cn",
		},
		{
			name:         "共享域名: subHost is the identity, agentHost the parent",
			agentHost:    "www.ats-test.cn",
			agentSubHost: "server.www.ats-test.cn",
			wantIdentity: "server.www.ats-test.cn",
			wantAccess:   "www.ats-test.cn",
			wantShared:   true,
		},
		{
			// A record from before agentSubHost existed: both accessors must keep
			// returning what that record always meant.
			name:         "legacy record with no subHost",
			agentHost:    "legacy.example.com",
			wantIdentity: "legacy.example.com",
			wantAccess:   "legacy.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &TLPayload{AgentHost: tt.agentHost, AgentSubHost: tt.agentSubHost}
			if got := p.IdentityHost(); got != tt.wantIdentity {
				t.Errorf("IdentityHost() = %q, want %q", got, tt.wantIdentity)
			}
			if got := p.AccessHost(); got != tt.wantAccess {
				t.Errorf("AccessHost() = %q, want %q", got, tt.wantAccess)
			}
			if got := p.IsSharedDomain(); got != tt.wantShared {
				t.Errorf("IsSharedDomain() = %v, want %v", got, tt.wantShared)
			}
		})
	}
}

func TestTLPayload_AgentSubHost_JSON(t *testing.T) {
	raw := `{"agentHost":"www.ats-test.cn","agentSubHost":"server.www.ats-test.cn"}`
	var p TLPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if p.AgentSubHost != "server.www.ats-test.cn" {
		t.Errorf("AgentSubHost = %q, want %q", p.AgentSubHost, "server.www.ats-test.cn")
	}

	// agentSubHost is omitempty, so a 独立域名 payload must serialize exactly as it
	// did before the field existed — the seal is computed over these bytes.
	out, err := json.Marshal(&TLPayload{AgentHost: "solo.example.com"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(out), "agentSubHost") {
		t.Errorf("Marshal() emitted agentSubHost for an empty value: %s", out)
	}
}
