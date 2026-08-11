package verify

import (
	"testing"
)

func TestParseATIRecord(t *testing.T) {
	tests := []struct {
		name         string
		txt          string
		wantErr      bool
		wantID       string
		wantRA       string
		wantVersion  string
		wantMode     ATIRecordMode
		wantProtocol string
		wantURL      string
	}{
		// --- New dual-hostname format (av/u fields) ---
		{
			name:         "new format: a2a protocol",
			txt:          "v=ati1; av=v1.0.0; p=a2a; u=https://platform.example.com/agents/ag-39dd66/a2a",
			wantID:       "ag-39dd66",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "a2a",
			wantURL:      "https://platform.example.com/agents/ag-39dd66/a2a",
		},
		{
			name:         "new format: mcp protocol",
			txt:          "v=ati1; av=v2.1.0; p=mcp; u=https://platform.example.com/agents/d6c78fcb-4992-418f-b784-e4a020d90207/mcp",
			wantID:       "d6c78fcb-4992-418f-b784-e4a020d90207",
			wantVersion:  "v2.1.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "mcp",
			wantURL:      "https://platform.example.com/agents/d6c78fcb-4992-418f-b784-e4a020d90207/mcp",
		},
		{
			name:         "new format: no spaces",
			txt:          "v=ati1;av=v1.0.0;p=a2a;u=https://example.com/agents/abc123/a2a",
			wantID:       "abc123",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "a2a",
			wantURL:      "https://example.com/agents/abc123/a2a",
		},
		{
			name:         "new format: av without url still works (direct mode)",
			txt:          "v=ati1; av=v1.0.0; p=a2a",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeDirect,
			wantProtocol: "a2a",
		},
		{
			name:         "new format: URL without /agents/ pattern (no ID extraction)",
			txt:          "v=ati1; av=v1.0.0; p=a2a; u=https://example.com/api/v1/endpoint",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "a2a",
			wantURL:      "https://example.com/api/v1/endpoint",
		},
		{
			name:         "new format: explicit id takes precedence over URL extraction",
			txt:          "v=ati1; id=explicit-id; av=v1.0.0; p=a2a; u=https://example.com/agents/url-id/a2a",
			wantID:       "explicit-id",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "a2a",
			wantURL:      "https://example.com/agents/url-id/a2a",
		},
		// --- Legacy format (version/ver, url fields) ---
		{
			name:         "legacy: complete card record",
			txt:          "v=ati1; id=ag-39dd66; ra=aliyun; version=v1.0.0; mode=card; p=mcp; url=https://example.com/.well-known/agent-card.json",
			wantID:       "ag-39dd66",
			wantRA:       "aliyun",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "mcp",
			wantURL:      "https://example.com/.well-known/agent-card.json",
		},
		{
			name:        "legacy: direct mode without protocol",
			txt:         "v=ati1; id=ag-abc123; ra=aliyun; version=v2.1.0; mode=direct",
			wantID:      "ag-abc123",
			wantRA:      "aliyun",
			wantVersion: "v2.1.0",
			wantMode:    ATIRecordModeDirect,
		},
		{
			name:         "legacy: direct mode with protocol",
			txt:          "v=ati1; id=ag-xyz; ra=aliyun; version=v1.0.0; mode=direct; p=a2a",
			wantID:       "ag-xyz",
			wantRA:       "aliyun",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeDirect,
			wantProtocol: "a2a",
		},
		{
			name:         "legacy: ver and proto aliases",
			txt:          "v=ati1; id=d6c78fcb-4992-418f-b784-e4a020d90207; ra=aliyun; ver=1.0.2; proto=A2A",
			wantID:       "d6c78fcb-4992-418f-b784-e4a020d90207",
			wantRA:       "aliyun",
			wantVersion:  "v1.0.2",
			wantMode:     ATIRecordModeDirect,
			wantProtocol: "A2A",
		},
		{
			name:         "legacy: minimal record without id/ra/mode",
			txt:          "v=ati1; version=v1.0.0; p=a2a; url=https://agent.example.com/.well-known/agent-card.json",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeCard,
			wantProtocol: "a2a",
			wantURL:      "https://agent.example.com/.well-known/agent-card.json",
		},
		{
			name:        "legacy: minimal record without url infers direct mode",
			txt:         "v=ati1; version=v1.0.0",
			wantVersion: "v1.0.0",
			wantMode:    ATIRecordModeDirect,
		},
		// --- Error cases ---
		{
			name:    "missing version field v",
			txt:     "id=ag-123; ra=aliyun; version=v1.0.0; mode=direct",
			wantErr: true,
		},
		{
			name:    "wrong version field",
			txt:     "v=ati2; id=ag-123; ra=aliyun; version=v1.0.0; mode=direct",
			wantErr: true,
		},
		{
			name:    "missing version and ver and av",
			txt:     "v=ati1; id=ag-123; ra=aliyun",
			wantErr: true,
		},
		{
			name:    "invalid version",
			txt:     "v=ati1; id=ag-123; ra=aliyun; version=bad; mode=direct",
			wantErr: true,
		},
		{
			name:    "invalid mode",
			txt:     "v=ati1; id=ag-123; ra=aliyun; version=v1.0.0; mode=unknown",
			wantErr: true,
		},
		{
			name:         "no spaces around semicolons",
			txt:          "v=ati1;id=ag-123;ra=aliyun;version=v1.0.0;mode=direct",
			wantID:       "ag-123",
			wantRA:       "aliyun",
			wantVersion:  "v1.0.0",
			wantMode:     ATIRecordModeDirect,
			wantProtocol: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := ParseATIRecord(tt.txt)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseATIRecord(%q) expected error, got nil", tt.txt)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseATIRecord(%q) unexpected error: %v", tt.txt, err)
			}
			if record.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", record.ID, tt.wantID)
			}
			if record.RA != tt.wantRA {
				t.Errorf("RA = %q, want %q", record.RA, tt.wantRA)
			}
			if record.Version.String() != tt.wantVersion {
				t.Errorf("Version = %q, want %q", record.Version.String(), tt.wantVersion)
			}
			if record.Mode != tt.wantMode {
				t.Errorf("Mode = %v, want %v", record.Mode, tt.wantMode)
			}
			if record.Protocol != tt.wantProtocol {
				t.Errorf("Protocol = %q, want %q", record.Protocol, tt.wantProtocol)
			}
			if record.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", record.URL, tt.wantURL)
			}
		})
	}
}

func TestExtractAgentIDFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://platform.example.com/agents/ag-39dd66/a2a", "ag-39dd66"},
		{"https://platform.example.com/agents/d6c78fcb-4992-418f-b784-e4a020d90207/mcp", "d6c78fcb-4992-418f-b784-e4a020d90207"},
		{"https://example.com/agents/abc123/a2a", "abc123"},
		{"https://example.com/v1/agents/my-agent/endpoint", "my-agent"},
		{"https://example.com/api/v1/endpoint", ""},
		{"https://example.com/agents/", ""},
		{"https://example.com/agents/only-id", "only-id"},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractAgentIDFromURL(tt.url)
		if got != tt.want {
			t.Errorf("extractAgentIDFromURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestATIRecordMode_String(t *testing.T) {
	tests := []struct {
		mode ATIRecordMode
		want string
	}{
		{ATIRecordModeCard, "card"},
		{ATIRecordModeDirect, "direct"},
		{ATIRecordMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("ATIRecordMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}
