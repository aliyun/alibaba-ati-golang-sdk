package verify

import (
	"net/url"
	"strings"
	"testing"
)

func TestRewriteBadgeURLHost_WithPort(t *testing.T) {
	rawURL := "https://rogue.example.com:8443/badge/abc123"
	trustedHost := "tl.ansagent.cn"

	result, err := RewriteBadgeURLHost(rawURL, trustedHost)
	if err != nil {
		t.Fatalf("RewriteBadgeURLHost() unexpected error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result URL is not parseable: %v", err)
	}

	if parsed.Hostname() != trustedHost {
		t.Errorf("hostname = %q, want %q", parsed.Hostname(), trustedHost)
	}
	if parsed.Port() != "8443" {
		t.Errorf("port = %q, want %q", parsed.Port(), "8443")
	}
}

func TestRewriteBadgeURLHost_WithoutPort(t *testing.T) {
	rawURL := "https://rogue.example.com/badge/abc123"
	trustedHost := "tl.ansagent.cn"

	result, err := RewriteBadgeURLHost(rawURL, trustedHost)
	if err != nil {
		t.Fatalf("RewriteBadgeURLHost() unexpected error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result URL is not parseable: %v", err)
	}

	if parsed.Hostname() != trustedHost {
		t.Errorf("hostname = %q, want %q", parsed.Hostname(), trustedHost)
	}
	if parsed.Port() != "" {
		t.Errorf("port = %q, want empty", parsed.Port())
	}
}

func TestRewriteBadgeURLHost_PathAndQueryPreserved(t *testing.T) {
	rawURL := "https://rogue.example.com:8443/path/to/badge?id=abc123&format=json"
	trustedHost := "tl.ansagent.cn"

	result, err := RewriteBadgeURLHost(rawURL, trustedHost)
	if err != nil {
		t.Fatalf("RewriteBadgeURLHost() unexpected error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result URL is not parseable: %v", err)
	}

	if parsed.Path != "/path/to/badge" {
		t.Errorf("path = %q, want %q", parsed.Path, "/path/to/badge")
	}
	if parsed.RawQuery != "id=abc123&format=json" {
		t.Errorf("raw query = %q, want %q", parsed.RawQuery, "id=abc123&format=json")
	}
	if parsed.Hostname() != trustedHost {
		t.Errorf("hostname = %q, want %q", parsed.Hostname(), trustedHost)
	}
	if parsed.Port() != "8443" {
		t.Errorf("port = %q, want %q", parsed.Port(), "8443")
	}
}

func TestRewriteBadgeURLHost_InvalidURL(t *testing.T) {
	// url.Parse is fairly lenient; use a control character to force a parse error.
	invalidURL := "ht\x7fps://[::1"
	trustedHost := "tl.ansagent.cn"

	_, err := RewriteBadgeURLHost(invalidURL, trustedHost)
	if err == nil {
		t.Fatal("RewriteBadgeURLHost() expected error for invalid URL, got nil")
	}
	if !strings.Contains(err.Error(), "invalid badge URL") {
		t.Errorf("error message = %q, want it to contain 'invalid badge URL'", err.Error())
	}
}

func TestRewriteBadgeURLHost_HTTPScheme(t *testing.T) {
	rawURL := "http://rogue.example.com:8080/badge/abc123"
	trustedHost := "tl.ansagent.cn"

	result, err := RewriteBadgeURLHost(rawURL, trustedHost)
	if err != nil {
		t.Fatalf("RewriteBadgeURLHost() unexpected error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result URL is not parseable: %v", err)
	}

	if parsed.Scheme != "http" {
		t.Errorf("scheme = %q, want %q", parsed.Scheme, "http")
	}
	if parsed.Hostname() != trustedHost {
		t.Errorf("hostname = %q, want %q", parsed.Hostname(), trustedHost)
	}
	if parsed.Port() != "8080" {
		t.Errorf("port = %q, want %q", parsed.Port(), "8080")
	}
}

func TestRewriteBadgeURLHost_HTTPSScheme(t *testing.T) {
	rawURL := "https://rogue.example.com:443/badge/abc123"
	trustedHost := "tl.ansagent.cn"

	result, err := RewriteBadgeURLHost(rawURL, trustedHost)
	if err != nil {
		t.Fatalf("RewriteBadgeURLHost() unexpected error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result URL is not parseable: %v", err)
	}

	if parsed.Scheme != "https" {
		t.Errorf("scheme = %q, want %q", parsed.Scheme, "https")
	}
	if parsed.Hostname() != trustedHost {
		t.Errorf("hostname = %q, want %q", parsed.Hostname(), trustedHost)
	}
	if parsed.Port() != "443" {
		t.Errorf("port = %q, want %q", parsed.Port(), "443")
	}
}

func TestRewriteBadgeURLHost_EmptyHost(t *testing.T) {
	// Even with an empty original host, the trusted host replaces it.
	rawURL := "/badge/abc123"
	trustedHost := "tl.ansagent.cn"

	result, err := RewriteBadgeURLHost(rawURL, trustedHost)
	if err != nil {
		t.Fatalf("RewriteBadgeURLHost() unexpected error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("result URL is not parseable: %v", err)
	}

	if parsed.Host != trustedHost {
		t.Errorf("host = %q, want %q", parsed.Host, trustedHost)
	}
}

func TestRewriteBadgeURLHost_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		trustedHost string
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{
			name:        "https with port",
			rawURL:      "https://evil.com:8443/badge",
			trustedHost: "trusted.example.com",
			wantHost:    "trusted.example.com",
			wantPort:    "8443",
		},
		{
			name:        "https without port",
			rawURL:      "https://evil.com/badge",
			trustedHost: "trusted.example.com",
			wantHost:    "trusted.example.com",
			wantPort:    "",
		},
		{
			name:        "http with port",
			rawURL:      "http://evil.com:8080/badge",
			trustedHost: "trusted.example.com",
			wantHost:    "trusted.example.com",
			wantPort:    "8080",
		},
		{
			name:        "with path and query",
			rawURL:      "https://evil.com:443/a/b?c=d",
			trustedHost: "trusted.example.com",
			wantHost:    "trusted.example.com",
			wantPort:    "443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RewriteBadgeURLHost(tt.rawURL, tt.trustedHost)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RewriteBadgeURLHost() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			parsed, err := url.Parse(result)
			if err != nil {
				t.Fatalf("result URL is not parseable: %v", err)
			}
			if parsed.Hostname() != tt.wantHost {
				t.Errorf("hostname = %q, want %q", parsed.Hostname(), tt.wantHost)
			}
			if parsed.Port() != tt.wantPort {
				t.Errorf("port = %q, want %q", parsed.Port(), tt.wantPort)
			}
		})
	}
}
