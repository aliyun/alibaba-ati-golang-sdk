package ati

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAgentClient_Defaults(t *testing.T) {
	client, err := NewAgentClient()
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	if client.Policy() != PolicyBadgeRequired {
		t.Errorf("default policy = %v, want PolicyBadgeRequired", client.Policy())
	}
	if client.HTTPClient() == nil {
		t.Error("HTTPClient() returned nil")
	}
	if client.tlBaseURL != "https://tl.ansagent.cn" {
		t.Errorf("default tlBaseURL = %v, want https://tl.ansagent.cn", client.tlBaseURL)
	}
}

func TestNewAgentClient_WithOptions(t *testing.T) {
	client, err := NewAgentClient(
		WithClientPolicy(PolicyPKIOnly),
		WithClientTLBaseURL("https://custom.example.com"),
	)
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	if client.Policy() != PolicyPKIOnly {
		t.Errorf("policy = %v, want PolicyPKIOnly", client.Policy())
	}
	if client.tlBaseURL != "https://custom.example.com" {
		t.Errorf("tlBaseURL = %v, want https://custom.example.com", client.tlBaseURL)
	}
}

func TestNewAgentClient_WithDiscoverer(t *testing.T) {
	disc := &mockDiscoverer{}
	client, err := NewAgentClient(WithDiscoverer(disc))
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	if client.discoverer != disc {
		t.Error("discoverer not set")
	}
}

func TestNewAgentClient_WithVerifyConnection(t *testing.T) {
	called := false
	fn := func(tls.ConnectionState) error {
		called = true
		return nil
	}
	client, err := NewAgentClient(WithVerifyConnection(fn))
	if err != nil {
		t.Fatalf("NewAgentClient() error = %v", err)
	}
	_ = client
	_ = called
}

func TestAgentClient_Do(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client, _ := NewAgentClient()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestAgentClient_Get(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, _ := NewAgentClient()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestAgentClient_Post(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "hello" {
			t.Errorf("body = %s, want hello", string(body))
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client, _ := NewAgentClient()
	resp, err := client.Post(srv.URL, "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want 201", resp.StatusCode)
	}
}

func TestAgentClient_HTTPClient_NotNil(t *testing.T) {
	client, _ := NewAgentClient()
	hc := client.HTTPClient()
	if hc == nil {
		t.Fatal("HTTPClient() returned nil")
	}
	transport, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3 (%d)", transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
}
