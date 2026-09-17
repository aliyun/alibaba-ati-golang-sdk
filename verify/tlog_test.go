package verify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func TestMockTransparencyLogClient(t *testing.T) {
	tlResp := &models.TLResponse{
		Status:        string(models.TLStatusActive),
		SchemaVersion: "V1",
		Payload: models.TLPayload{
			LogID:       "test-log-id",
			AgentName:   "ati://v1.0.0.agent.example.com",
			AgentHost:   "agent.example.com",
			AgentStatus: string(models.TLStatusActive),
			Version:     "v1.0.0",
			Certificates: models.TLCertificates{
				ServerCertFingerprint:   "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
				IdentityCertFingerprint: "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496",
			},
		},
	}

	t.Run("FetchTLResponse success", func(t *testing.T) {
		client := NewMockTransparencyLogClient().
			WithTLResponse("https://tlog.example.com/badge", tlResp)

		result, err := client.FetchTLResponse(context.Background(), "https://tlog.example.com/badge")
		if err != nil {
			t.Fatalf("FetchTLResponse() error = %v", err)
		}
		if result == nil {
			t.Fatal("FetchTLResponse() returned nil")
		}
		if result.Payload.AgentStatus != string(models.TLStatusActive) {
			t.Errorf("AgentStatus = %v, want ACTIVE", result.Payload.AgentStatus)
		}
		if result.Payload.AgentHost != "agent.example.com" {
			t.Errorf("AgentHost = %q, want agent.example.com", result.Payload.AgentHost)
		}
	})

	t.Run("FetchTLResponse not found", func(t *testing.T) {
		client := NewMockTransparencyLogClient()

		_, err := client.FetchTLResponse(context.Background(), "https://tlog.example.com/unknown")
		if err == nil {
			t.Fatal("FetchTLResponse() expected error, got nil")
		}
		var tlogErr *TlogError
		if !errors.As(err, &tlogErr) {
			t.Fatalf("expected *TlogError, got %T", err)
		}
		if tlogErr.Type != TlogErrorNotFound {
			t.Errorf("error type = %v, want TlogErrorNotFound", tlogErr.Type)
		}
	})

	t.Run("FetchTLResponse error", func(t *testing.T) {
		client := NewMockTransparencyLogClient().
			WithError("https://tlog.example.com/error", &TlogError{
				Type: TlogErrorServiceUnavailable,
				URL:  "https://tlog.example.com/error",
			})

		_, err := client.FetchTLResponse(context.Background(), "https://tlog.example.com/error")
		if err == nil {
			t.Fatal("FetchTLResponse() expected error, got nil")
		}
		var tlogErr *TlogError
		if !errors.As(err, &tlogErr) {
			t.Fatalf("expected *TlogError, got %T", err)
		}
		if tlogErr.Type != TlogErrorServiceUnavailable {
			t.Errorf("error type = %v, want TlogErrorServiceUnavailable", tlogErr.Type)
		}
	})
}

func TestHTTPTransparencyLogClient_FetchTLResponse_Success(t *testing.T) {
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			LogID:       "test-log",
			AgentStatus: string(models.TLStatusActive),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tlResp)
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	result, err := client.FetchTLResponse(context.Background(), server.URL+"/badge/123")
	if err != nil {
		t.Fatalf("FetchTLResponse() error = %v", err)
	}
	if result.Payload.AgentStatus != string(models.TLStatusActive) {
		t.Errorf("AgentStatus = %v, want %v", result.Payload.AgentStatus, models.TLStatusActive)
	}
}

func TestHTTPTransparencyLogClient_FetchTLResponse_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchTLResponse(context.Background(), server.URL+"/badge/missing")
	if err == nil {
		t.Fatal("FetchTLResponse() expected error for 404")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorNotFound {
		t.Errorf("Type = %v, want TlogErrorNotFound", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchTLResponse_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchTLResponse(context.Background(), server.URL+"/badge/123")
	if err == nil {
		t.Fatal("FetchTLResponse() expected error for 500")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorServiceUnavailable {
		t.Errorf("Type = %v, want TlogErrorServiceUnavailable", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchTLResponse_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchTLResponse(context.Background(), server.URL+"/badge/123")
	if err == nil {
		t.Fatal("FetchTLResponse() expected error for 400")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorInvalidResponse {
		t.Errorf("Type = %v, want TlogErrorInvalidResponse", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchTLResponse_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchTLResponse(context.Background(), server.URL+"/badge/123")
	if err == nil {
		t.Fatal("FetchTLResponse() expected error for invalid JSON")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorInvalidResponse {
		t.Errorf("Type = %v, want TlogErrorInvalidResponse", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchTLResponse_ConnectionError(t *testing.T) {
	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchTLResponse(context.Background(), "http://localhost:1/badge/123")
	if err == nil {
		t.Fatal("FetchTLResponse() expected error for connection refused")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorServiceUnavailable {
		t.Errorf("Type = %v, want TlogErrorServiceUnavailable", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_WithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	client := NewHTTPTransparencyLogClient().WithHTTPClient(customClient)
	if client.httpClient != customClient {
		t.Error("WithHTTPClient() did not set custom client")
	}
}

func TestHTTPTransparencyLogClient_WithTimeout(t *testing.T) {
	client := NewHTTPTransparencyLogClient().WithTimeout(10 * time.Second)
	if client.httpClient.Timeout != 10*time.Second {
		t.Errorf("WithTimeout() timeout = %v, want 10s", client.httpClient.Timeout)
	}
}
