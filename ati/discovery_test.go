package ati

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// startMockRegistryServer starts a httptest server that simulates the ANS registry API.
// It returns the server URL and a function to inspect the last received request.
func startMockRegistryServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(func() { server.Close() })
	return server.URL
}

func defaultMockRegistryHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock registry received: %s %s", r.Method, r.URL.String())

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"agents": []map[string]any{
				{
					"agentDisplayName": "test",
					"agentHost":        "test.com",
					"version":          "1.0",
				},
			},
			"totalCount":    1,
			"returnedCount": 1,
			"limit":         20,
			"offset":        0,
			"hasMore":       false,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to write mock response: %v", err)
		}
	}
}

func TestDiscoverAgents_NoSearchCriteria(t *testing.T) {
	_, err := DiscoverAgents(context.Background())
	if err == nil {
		t.Fatal("DiscoverAgents() expected error for no criteria, got nil")
	}
	if !strings.Contains(err.Error(), "at least one search criterion is required") {
		t.Errorf("DiscoverAgents() error = %q, want to contain %q",
			err.Error(), "at least one search criterion is required")
	}
}

func TestDiscoverAgents_WithSearchNameOnly(t *testing.T) {
	serverURL := startMockRegistryServer(t, defaultMockRegistryHandler(t))

	resp, err := DiscoverAgents(context.Background(),
		WithSearchName("test"),
		WithRegistryURL(serverURL),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if resp == nil {
		t.Fatal("DiscoverAgents() returned nil response")
	}
	if len(resp.Agents) != 1 {
		t.Fatalf("Agents length = %d, want 1", len(resp.Agents))
	}
	if resp.Agents[0].AgentDisplayName != "test" {
		t.Errorf("Agents[0].AgentDisplayName = %q, want %q",
			resp.Agents[0].AgentDisplayName, "test")
	}
	if resp.Agents[0].AgentHost != "test.com" {
		t.Errorf("Agents[0].AgentHost = %q, want %q",
			resp.Agents[0].AgentHost, "test.com")
	}
	if resp.Agents[0].Version != "1.0" {
		t.Errorf("Agents[0].Version = %q, want %q",
			resp.Agents[0].Version, "1.0")
	}
}

func TestDiscoverAgents_WithSearchHost(t *testing.T) {
	var capturedParams url.Values
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedParams = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents":      []any{},
			"totalCount":  0,
			"returnedCount": 0,
			"limit":       20,
			"offset":      0,
			"hasMore":     false,
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	resp, err := DiscoverAgents(context.Background(),
		WithSearchHost("example.com"),
		WithRegistryURL(serverURL),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if resp == nil {
		t.Fatal("DiscoverAgents() returned nil")
	}
	if got := capturedParams.Get("agentHost"); got != "example.com" {
		t.Errorf("query param agentHost = %q, want %q", got, "example.com")
	}
}

func TestDiscoverAgents_WithSearchVersion(t *testing.T) {
	var capturedParams url.Values
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedParams = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents":      []any{},
			"totalCount":  0,
			"returnedCount": 0,
			"limit":       20,
			"offset":      0,
			"hasMore":     false,
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	_, err := DiscoverAgents(context.Background(),
		WithSearchVersion("1.0.0"),
		WithRegistryURL(serverURL),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if got := capturedParams.Get("version"); got != "1.0.0" {
		t.Errorf("query param version = %q, want %q", got, "1.0.0")
	}
}

func TestDiscoverAgents_WithSearchLimit(t *testing.T) {
	var capturedParams url.Values
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedParams = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents":      []any{},
			"totalCount":  0,
			"returnedCount": 0,
			"limit":       50,
			"offset":      0,
			"hasMore":     false,
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	_, err := DiscoverAgents(context.Background(),
		WithSearchName("test"),
		WithSearchLimit(50),
		WithRegistryURL(serverURL),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if got := capturedParams.Get("limit"); got != "50" {
		t.Errorf("query param limit = %q, want %q", got, "50")
	}
}

func TestDiscoverAgents_WithSearchOffset(t *testing.T) {
	var capturedParams url.Values
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedParams = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents":      []any{},
			"totalCount":  0,
			"returnedCount": 0,
			"limit":       20,
			"offset":      10,
			"hasMore":     false,
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	_, err := DiscoverAgents(context.Background(),
		WithSearchName("test"),
		WithSearchOffset(10),
		WithRegistryURL(serverURL),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if got := capturedParams.Get("offset"); got != "10" {
		t.Errorf("query param offset = %q, want %q", got, "10")
	}
}

func TestDiscoverAgents_WithRegistryAuth(t *testing.T) {
	var capturedAuth string
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents":      []any{},
			"totalCount":  0,
			"returnedCount": 0,
			"limit":       20,
			"offset":      0,
			"hasMore":     false,
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	_, err := DiscoverAgents(context.Background(),
		WithSearchName("test"),
		WithRegistryURL(serverURL),
		WithRegistryAuth("mykey", "mysecret"),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if capturedAuth == "" {
		t.Fatal("Authorization header not set")
	}
	if !strings.HasPrefix(capturedAuth, "sso-key ") {
		t.Errorf("Authorization = %q, want to start with %q", capturedAuth, "sso-key ")
	}
	if !strings.Contains(capturedAuth, "mykey") {
		t.Errorf("Authorization = %q, want to contain %q", capturedAuth, "mykey")
	}
	if !strings.Contains(capturedAuth, "mysecret") {
		t.Errorf("Authorization = %q, want to contain %q", capturedAuth, "mysecret")
	}
}

func TestDiscoverAgents_RegistryReturnsError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"code":    "INTERNAL_ERROR",
			"message": "internal server error",
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	_, err := DiscoverAgents(context.Background(),
		WithSearchName("test"),
		WithRegistryURL(serverURL),
	)
	if err == nil {
		t.Fatal("DiscoverAgents() expected error for registry error, got nil")
	}
	// The error should wrap the registry error
	if !strings.Contains(err.Error(), "agent search failed") {
		t.Errorf("DiscoverAgents() error = %q, want to contain %q",
			err.Error(), "agent search failed")
	}
}

func TestDiscoverAgents_RegistryReturnsBadRequest(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"code":    "INVALID_REQUEST",
			"message": "invalid search parameters",
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	_, err := DiscoverAgents(context.Background(),
		WithSearchName("test"),
		WithRegistryURL(serverURL),
	)
	if err == nil {
		t.Fatal("DiscoverAgents() expected error for bad request, got nil")
	}
}

func TestDiscoverAgents_ContextCancelled(t *testing.T) {
	serverURL := startMockRegistryServer(t, defaultMockRegistryHandler(t))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DiscoverAgents(ctx,
		WithSearchName("test"),
		WithRegistryURL(serverURL),
	)
	if err == nil {
		t.Fatal("DiscoverAgents() expected error for cancelled context, got nil")
	}
}

func TestDiscoverAgents_AllCriteriaCombined(t *testing.T) {
	var capturedParams url.Values
	handler := func(w http.ResponseWriter, r *http.Request) {
		capturedParams = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents": []map[string]any{
				{
					"agentDisplayName": "multi-test",
					"agentHost":        "multi.example.com",
					"version":          "2.0.0",
				},
			},
			"totalCount":    1,
			"returnedCount": 1,
			"limit":         5,
			"offset":        3,
			"hasMore":       false,
		})
	}
	serverURL := startMockRegistryServer(t, handler)

	resp, err := DiscoverAgents(context.Background(),
		WithSearchName("multi-test"),
		WithSearchHost("multi.example.com"),
		WithSearchVersion("2.0.0"),
		WithSearchLimit(5),
		WithSearchOffset(3),
		WithRegistryURL(serverURL),
	)
	if err != nil {
		t.Fatalf("DiscoverAgents() error = %v", err)
	}
	if resp == nil {
		t.Fatal("DiscoverAgents() returned nil")
	}
	if len(resp.Agents) != 1 {
		t.Fatalf("Agents length = %d, want 1", len(resp.Agents))
	}
	// Verify all query params were sent
	if got := capturedParams.Get("agentDisplayName"); got != "multi-test" {
		t.Errorf("agentDisplayName = %q, want %q", got, "multi-test")
	}
	if got := capturedParams.Get("agentHost"); got != "multi.example.com" {
		t.Errorf("agentHost = %q, want %q", got, "multi.example.com")
	}
	if got := capturedParams.Get("version"); got != "2.0.0" {
		t.Errorf("version = %q, want %q", got, "2.0.0")
	}
	if got := capturedParams.Get("limit"); got != "5" {
		t.Errorf("limit = %q, want %q", got, "5")
	}
	if got := capturedParams.Get("offset"); got != "3" {
		t.Errorf("offset = %q, want %q", got, "3")
	}
}

// Test the option functions in isolation to verify they mutate the config correctly.
func TestDiscoveryOptions(t *testing.T) {
	t.Run("WithSearchName", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithSearchName("foo")(cfg)
		if cfg.name != "foo" {
			t.Errorf("name = %q, want %q", cfg.name, "foo")
		}
	})

	t.Run("WithSearchHost", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithSearchHost("bar.com")(cfg)
		if cfg.host != "bar.com" {
			t.Errorf("host = %q, want %q", cfg.host, "bar.com")
		}
	})

	t.Run("WithSearchVersion", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithSearchVersion("1.0.0")(cfg)
		if cfg.version != "1.0.0" {
			t.Errorf("version = %q, want %q", cfg.version, "1.0.0")
		}
	})

	t.Run("WithSearchLimit", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithSearchLimit(100)(cfg)
		if cfg.limit != 100 {
			t.Errorf("limit = %d, want 100", cfg.limit)
		}
	})

	t.Run("WithSearchOffset", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithSearchOffset(20)(cfg)
		if cfg.offset != 20 {
			t.Errorf("offset = %d, want 20", cfg.offset)
		}
	})

	t.Run("WithRegistryURL", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithRegistryURL("https://custom.example.com")(cfg)
		if cfg.registryURL != "https://custom.example.com" {
			t.Errorf("registryURL = %q, want %q", cfg.registryURL, "https://custom.example.com")
		}
	})

	t.Run("WithRegistryAuth", func(t *testing.T) {
		cfg := &discoveryConfig{}
		WithRegistryAuth("key", "secret")(cfg)
		if cfg.apiKey != "key" {
			t.Errorf("apiKey = %q, want %q", cfg.apiKey, "key")
		}
		if cfg.apiSecret != "secret" {
			t.Errorf("apiSecret = %q, want %q", cfg.apiSecret, "secret")
		}
	})
}
