package verify

import (
	"testing"
)

func TestParseATIRecord_Valid(t *testing.T) {
	txt := "v=ati1; id=agent-001; ra=https://ra.example.com; ver=1.0.0; proto=HTTPS; mode=standard"
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.FormatVersion != "ati1" {
		t.Errorf("FormatVersion = %q, want ati1", record.FormatVersion)
	}
	if record.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", record.AgentID)
	}
	if record.RAEndpoint != "https://ra.example.com" {
		t.Errorf("RAEndpoint = %q", record.RAEndpoint)
	}
	if record.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", record.Version)
	}
	if record.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want HTTPS", record.Protocol)
	}
	if record.Mode != "standard" {
		t.Errorf("Mode = %q, want standard", record.Mode)
	}
}

func TestParseATIRecord_WithURL(t *testing.T) {
	txt := "v=ati1; id=agent-002; url=https://tl.example.com/badge/002"
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.URL != "https://tl.example.com/badge/002" {
		t.Errorf("URL = %q", record.URL)
	}
	if record.AgentID != "agent-002" {
		t.Errorf("AgentID = %q, want agent-002", record.AgentID)
	}
}

func TestParseATIRecord_MinimalValid(t *testing.T) {
	txt := "v=ati1"
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.FormatVersion != "ati1" {
		t.Errorf("FormatVersion = %q, want ati1", record.FormatVersion)
	}
	if record.AgentID != "" {
		t.Errorf("AgentID = %q, want empty", record.AgentID)
	}
}

func TestParseATIRecord_EmptyString(t *testing.T) {
	_, err := ParseATIRecord("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParseATIRecord_MissingVersion(t *testing.T) {
	_, err := ParseATIRecord("id=agent-001; ra=https://ra.example.com")
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestParseATIRecord_UnsupportedVersion(t *testing.T) {
	_, err := ParseATIRecord("v=ati2; id=agent-001")
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseATIRecord_ExtraWhitespace(t *testing.T) {
	txt := "  v=ati1 ;  id=agent-003 ;  ver=2.0.0  "
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.AgentID != "agent-003" {
		t.Errorf("AgentID = %q, want agent-003", record.AgentID)
	}
	if record.Version != "2.0.0" {
		t.Errorf("Version = %q, want 2.0.0", record.Version)
	}
}

func TestParseATIRecord_EmptyParts(t *testing.T) {
	txt := "v=ati1;;; id=agent-004"
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.AgentID != "agent-004" {
		t.Errorf("AgentID = %q, want agent-004", record.AgentID)
	}
}

func TestParseATIRecord_UnknownFields(t *testing.T) {
	txt := "v=ati1; id=agent-005; unknown=value; custom=data"
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.AgentID != "agent-005" {
		t.Errorf("AgentID = %q, want agent-005", record.AgentID)
	}
}

func TestParseATIRecord_AllFields(t *testing.T) {
	txt := "v=ati1; id=full-agent; ra=https://ra.full.com; ver=3.0.0; proto=HTTP; mode=advanced; url=https://badge.full.com/123"
	record, err := ParseATIRecord(txt)
	if err != nil {
		t.Fatalf("ParseATIRecord() error = %v", err)
	}
	if record.FormatVersion != "ati1" {
		t.Errorf("FormatVersion = %q", record.FormatVersion)
	}
	if record.AgentID != "full-agent" {
		t.Errorf("AgentID = %q", record.AgentID)
	}
	if record.RAEndpoint != "https://ra.full.com" {
		t.Errorf("RAEndpoint = %q", record.RAEndpoint)
	}
	if record.Version != "3.0.0" {
		t.Errorf("Version = %q", record.Version)
	}
	if record.Protocol != "HTTP" {
		t.Errorf("Protocol = %q", record.Protocol)
	}
	if record.Mode != "advanced" {
		t.Errorf("Mode = %q", record.Mode)
	}
	if record.URL != "https://badge.full.com/123" {
		t.Errorf("URL = %q", record.URL)
	}
}

func TestATIRecord_StructFields(t *testing.T) {
	record := &ATIRecord{
		FormatVersion: "ati1",
		AgentID:       "test-id",
		RAEndpoint:    "https://ra.test.com",
		Version:       "1.0.0",
		Protocol:      "HTTPS",
		Mode:          "normal",
		URL:           "https://tl.test.com/badge",
	}

	if record.FormatVersion != "ati1" {
		t.Errorf("FormatVersion = %q", record.FormatVersion)
	}
	if record.AgentID != "test-id" {
		t.Errorf("AgentID = %q", record.AgentID)
	}
}
