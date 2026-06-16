package models

import (
	"testing"
)

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
			got := tt.status.IsValidForConnection()
			if got != tt.want {
				t.Errorf("IsValidForConnection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status TLAgentStatus
		want   bool
	}{
		{TLStatusActive, false},
		{TLStatusWarning, false},
		{TLStatusDeprecated, false},
		{TLStatusExpired, true},
		{TLStatusRevoked, true},
		{TLAgentStatus("UNKNOWN"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.IsTerminal()
			if got != tt.want {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTLAgentStatus_Constants(t *testing.T) {
	if TLStatusActive != "ACTIVE" {
		t.Errorf("TLStatusActive = %q", TLStatusActive)
	}
	if TLStatusWarning != "WARNING" {
		t.Errorf("TLStatusWarning = %q", TLStatusWarning)
	}
	if TLStatusDeprecated != "DEPRECATED" {
		t.Errorf("TLStatusDeprecated = %q", TLStatusDeprecated)
	}
	if TLStatusExpired != "EXPIRED" {
		t.Errorf("TLStatusExpired = %q", TLStatusExpired)
	}
	if TLStatusRevoked != "REVOKED" {
		t.Errorf("TLStatusRevoked = %q", TLStatusRevoked)
	}
}

func TestTLPayload_Fingerprints(t *testing.T) {
	payload := TLPayload{
		LogID:            "log-001",
		AgentID:          "agent-001",
		AgentName:        "test-agent",
		AgentDisplayName: "Test Agent",
		AgentHost:        "agent.example.com",
		AgentStatus:      "ACTIVE",
		Version:          "1.0.0",
		Certificates: TLCertificates{
			ServerCertFingerprint:   "sha256:abc123",
			IdentityCertFingerprint: "sha256:def456",
		},
	}

	if payload.ServerCertFingerprint() != "sha256:abc123" {
		t.Errorf("ServerCertFingerprint() = %q, want sha256:abc123", payload.ServerCertFingerprint())
	}
	if payload.IdentityCertFingerprint() != "sha256:def456" {
		t.Errorf("IdentityCertFingerprint() = %q, want sha256:def456", payload.IdentityCertFingerprint())
	}
}

func TestTLCertificates_Fields(t *testing.T) {
	certs := TLCertificates{
		ServerCertFingerprint:   "fp1",
		IdentityCertFingerprint: "fp2",
	}
	if certs.ServerCertFingerprint != "fp1" {
		t.Errorf("ServerCertFingerprint = %q", certs.ServerCertFingerprint)
	}
	if certs.IdentityCertFingerprint != "fp2" {
		t.Errorf("IdentityCertFingerprint = %q", certs.IdentityCertFingerprint)
	}
}

func TestTLResponse_Fields(t *testing.T) {
	resp := TLResponse{
		Status:        "ok",
		SchemaVersion: "1.0",
		Payload: TLPayload{
			AgentID: "agent-001",
			Version: "1.0.0",
		},
	}
	if resp.Status != "ok" {
		t.Errorf("Status = %q", resp.Status)
	}
	if resp.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q", resp.SchemaVersion)
	}
	if resp.Payload.AgentID != "agent-001" {
		t.Errorf("Payload.AgentID = %q", resp.Payload.AgentID)
	}
}

func TestTLPayload_EmptyFingerprints(t *testing.T) {
	payload := TLPayload{}
	if payload.ServerCertFingerprint() != "" {
		t.Errorf("ServerCertFingerprint() = %q, want empty", payload.ServerCertFingerprint())
	}
	if payload.IdentityCertFingerprint() != "" {
		t.Errorf("IdentityCertFingerprint() = %q, want empty", payload.IdentityCertFingerprint())
	}
}
