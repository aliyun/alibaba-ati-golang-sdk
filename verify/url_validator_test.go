package verify

import (
	"errors"
	"testing"
)

func TestURLValidator_Validate(t *testing.T) {
	validator := NewURLValidator([]string{
		"tl.ansagent.cn",
	})

	tests := []struct {
		name        string
		url         string
		wantErr     bool
		wantErrType URLErrorType
	}{
		{
			name: "valid trusted domain with port 8180",
			url:  "https://tl.ansagent.cn:8180/ans/api/v1/tl/agents/test-id/logs/latest",
		},
		{
			name: "valid trusted domain case insensitive",
			url:  "https://TL.ANSAGENT.CN:8180/ans/api/v1/tl/agents/test-id/logs/latest",
		},
		{
			name: "valid trusted domain port 443",
			url:  "https://tl.ansagent.cn:443/v1/agents/test-id",
		},
		{
			name: "valid trusted domain no port",
			url:  "https://tl.ansagent.cn/v1/agents/test-id",
		},
		{
			name:        "HTTP rejected",
			url:         "http://tl.ansagent.cn:8180/ans/api/v1/tl/agents/test-id",
			wantErr:     true,
			wantErrType: URLErrorHTTPScheme,
		},
		{
			name:        "untrusted domain",
			url:         "https://evil-transparency.attacker.com/v1/agents/test-id",
			wantErr:     true,
			wantErrType: URLErrorUntrustedDomain,
		},
		{
			name:        "trusted domain but non-standard port",
			url:         "https://tl.ansagent.cn:9999/v1/agents/test-id",
			wantErr:     true,
			wantErrType: URLErrorNonStandardPort,
		},
		{
			name:        "path traversal rejected",
			url:         "https://tl.ansagent.cn:8180/v1/agents/../../admin",
			wantErr:     true,
			wantErrType: URLErrorPathTraversal,
		},
		{
			name:        "query params rejected",
			url:         "https://tl.ansagent.cn:8180/v1/agents/test-id?admin=true",
			wantErr:     true,
			wantErrType: URLErrorPathTraversal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate(%q) expected error, got nil", tt.url)
					return
				}
				var urlErr *URLValidationError
				if !errors.As(err, &urlErr) {
					t.Errorf("Validate(%q) error type = %T, want *URLValidationError", tt.url, err)
					return
				}
				if urlErr.Type != tt.wantErrType {
					t.Errorf("Validate(%q) error type = %v, want %v", tt.url, urlErr.Type, tt.wantErrType)
				}
				return
			}
			if err != nil {
				t.Errorf("Validate(%q) unexpected error: %v", tt.url, err)
			}
		})
	}
}

func TestDefaultURLValidator(t *testing.T) {
	validator := NewDefaultURLValidator()

	// Trusted domain with port 8180 should pass
	if err := validator.Validate("https://tl.ansagent.cn:8180/ans/api/v1/tl/agents/test-id/logs/latest"); err != nil {
		t.Errorf("Default validator rejected trusted domain: %v", err)
	}

	// Untrusted domain should fail
	err := validator.Validate("https://evil.example.com/v1/agents/test-id")
	if err == nil {
		t.Error("Default validator accepted untrusted domain")
	}
}

func TestURLValidationError_Error(t *testing.T) {
	tests := []struct {
		name    string
		errType URLErrorType
		wantMsg string
	}{
		{
			name:    "HTTP scheme",
			errType: URLErrorHTTPScheme,
			wantMsg: "badge URL must use HTTPS: http://example.com",
		},
		{
			name:    "untrusted domain",
			errType: URLErrorUntrustedDomain,
			wantMsg: "badge URL domain not trusted: https://evil.com",
		},
		{
			name:    "non-standard port",
			errType: URLErrorNonStandardPort,
			wantMsg: "badge URL uses non-standard port: https://example.com:9999",
		},
		{
			name:    "path traversal",
			errType: URLErrorPathTraversal,
			wantMsg: "badge URL contains path traversal or query params: https://example.com/../admin",
		},
	}

	urls := map[URLErrorType]string{
		URLErrorHTTPScheme:      "http://example.com",
		URLErrorUntrustedDomain: "https://evil.com",
		URLErrorNonStandardPort: "https://example.com:9999",
		URLErrorPathTraversal:   "https://example.com/../admin",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &URLValidationError{Type: tt.errType, URL: urls[tt.errType]}
			if err.Error() != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantMsg)
			}
		})
	}
}
