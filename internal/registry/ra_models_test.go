package registry

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRAAgentInfo_JSON(t *testing.T) {
	now := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	info := &RAAgentInfo{
		AgentID:      "agent-001",
		ATIName:      "test-agent",
		AgentHost:    "agent.example.com",
		Version:      "1.0.0",
		Protocol:     "HTTPS",
		Mode:         "standard",
		Status:       "ACTIVE",
		RAEndpoint:   "https://ra.example.com",
		BadgeURL:     "https://tl.example.com/badge/001",
		RegisteredAt: now,
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got RAAgentInfo
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.AgentID != info.AgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, info.AgentID)
	}
	if got.ATIName != info.ATIName {
		t.Errorf("ATIName = %q, want %q", got.ATIName, info.ATIName)
	}
	if got.AgentHost != info.AgentHost {
		t.Errorf("AgentHost = %q, want %q", got.AgentHost, info.AgentHost)
	}
	if got.Status != info.Status {
		t.Errorf("Status = %q, want %q", got.Status, info.Status)
	}
}

func TestBadgeResponse_JSON(t *testing.T) {
	badge := &BadgeResponse{
		BadgeURL:    "https://tl.example.com/badge/001",
		BadgeStatus: "VALID",
		AgentStatus: "ACTIVE",
	}

	data, err := json.Marshal(badge)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got BadgeResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.BadgeURL != badge.BadgeURL {
		t.Errorf("BadgeURL = %q, want %q", got.BadgeURL, badge.BadgeURL)
	}
	if got.BadgeStatus != badge.BadgeStatus {
		t.Errorf("BadgeStatus = %q, want %q", got.BadgeStatus, badge.BadgeStatus)
	}
	if got.AgentStatus != badge.AgentStatus {
		t.Errorf("AgentStatus = %q, want %q", got.AgentStatus, badge.AgentStatus)
	}
}

func TestAuditTrailResponse_JSON(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	trail := &AuditTrailResponse{
		Records: []AuditRecord{
			{EventType: "REGISTER", Timestamp: now, Details: "Agent registered"},
			{EventType: "RENEW", Timestamp: now.Add(time.Hour)},
		},
		Total: 2,
	}

	data, err := json.Marshal(trail)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got AuditTrailResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.Total != 2 {
		t.Errorf("Total = %d, want 2", got.Total)
	}
	if len(got.Records) != 2 {
		t.Fatalf("Records length = %d, want 2", len(got.Records))
	}
	if got.Records[0].EventType != "REGISTER" {
		t.Errorf("Records[0].EventType = %q, want REGISTER", got.Records[0].EventType)
	}
	if got.Records[0].Details != "Agent registered" {
		t.Errorf("Records[0].Details = %q, want 'Agent registered'", got.Records[0].Details)
	}
	if got.Records[1].EventType != "RENEW" {
		t.Errorf("Records[1].EventType = %q, want RENEW", got.Records[1].EventType)
	}
}

func TestAgentRegistrationResponse_JSON(t *testing.T) {
	resp := &AgentRegistrationResponse{
		AgentID:   "agent-002",
		ATIName:   "new-agent",
		Status:    "PENDING",
		BadgeURL:  "https://tl.example.com/badge/002",
		ExpiresAt: "2026-01-01T00:00:00Z",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var got AgentRegistrationResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if got.AgentID != resp.AgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, resp.AgentID)
	}
	if got.Status != resp.Status {
		t.Errorf("Status = %q, want %q", got.Status, resp.Status)
	}
	if got.BadgeURL != resp.BadgeURL {
		t.Errorf("BadgeURL = %q, want %q", got.BadgeURL, resp.BadgeURL)
	}
}

func TestListConfig_Defaults(t *testing.T) {
	cfg := &listConfig{limit: 20, offset: 0}
	if cfg.limit != 20 {
		t.Errorf("default limit = %d, want 20", cfg.limit)
	}
	if cfg.offset != 0 {
		t.Errorf("default offset = %d, want 0", cfg.offset)
	}
	if cfg.host != "" {
		t.Errorf("default host = %q, want empty", cfg.host)
	}
}

func TestAuditConfig_Defaults(t *testing.T) {
	cfg := &auditConfig{limit: 20, offset: 0}
	if cfg.limit != 20 {
		t.Errorf("default limit = %d, want 20", cfg.limit)
	}
	if cfg.offset != 0 {
		t.Errorf("default offset = %d, want 0", cfg.offset)
	}
}
