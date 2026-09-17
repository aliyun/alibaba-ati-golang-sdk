package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Constructor / option tests ---

func TestNewAgentCardVerifier_Default(t *testing.T) {
	v := NewAgentCardVerifier(NewMockProducerKeyLookup())
	if v == nil {
		t.Fatal("NewAgentCardVerifier() = nil")
	}
	if v.httpClient == nil {
		t.Error("default httpClient is nil")
	}
	if v.logger == nil {
		t.Error("default logger is nil")
	}
}

func TestNewAgentCardVerifier_WithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 10 * time.Second}
	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(custom))
	if v.httpClient != custom {
		t.Error("WithAgentCardHTTPClient did not set custom client")
	}
}

func TestNewAgentCardVerifier_WithLogger(t *testing.T) {
	custom := slog.New(slog.NewTextHandler(nil, nil))
	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardLogger(custom))
	if v.logger != custom {
		t.Error("WithAgentCardLogger did not set custom logger")
	}
}

// --- VerifyAgentCard tests ---

func TestVerifyAgentCard_Server404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	_, err := v.VerifyAgentCard(context.Background(), server.URL, "")
	if err == nil {
		t.Fatal("VerifyAgentCard() = nil, want error for 404")
	}
	assertANSErrorCode(t, err, CodeAgentCardFetchFailed)
}

func TestVerifyAgentCard_NoCapabilitiesHash(t *testing.T) {
	cardBody := `{"agentId":"ans-card-001","agentName":"test-agent"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, "")
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	// With non-nil producerKeys, SignatureValid is set to true.
	if !result.SignatureValid {
		t.Error("SignatureValid = false, want true (producerKeys non-nil)")
	}
	// No capabilities hash provided, so CapHashValid should remain false.
	if result.CapHashValid {
		t.Error("CapHashValid = true, want false (no hash provided)")
	}
}

func TestVerifyAgentCard_MatchingCapabilitiesHash(t *testing.T) {
	cardBody := `{"agentId":"ans-card-001","agentName":"test-agent"}`

	// Compute the expected hash: JCS(cardBody) -> SHA-256 -> hex.
	canonical, err := JCSCanonicalize([]byte(cardBody))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	digest := sha256.Sum256(canonical)
	expectedHash := hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, expectedHash)
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if !result.CapHashValid {
		t.Error("CapHashValid = false, want true (matching hash)")
	}
}

func TestVerifyAgentCard_MatchingCapabilitiesHashWithPrefix(t *testing.T) {
	cardBody := `{"agentId":"ans-card-001","agentName":"test-agent"}`

	canonical, err := JCSCanonicalize([]byte(cardBody))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	digest := sha256.Sum256(canonical)
	expectedHash := "SHA256:" + hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, expectedHash)
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if !result.CapHashValid {
		t.Error("CapHashValid = false, want true (matching hash with SHA256: prefix)")
	}
}

func TestVerifyAgentCard_MatchingCapabilitiesHashWithLowercasePrefix(t *testing.T) {
	cardBody := `{"agentId":"ans-card-001","agentName":"test-agent"}`

	canonical, err := JCSCanonicalize([]byte(cardBody))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	digest := sha256.Sum256(canonical)
	expectedHash := "sha256:" + hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, expectedHash)
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if !result.CapHashValid {
		t.Error("CapHashValid = false, want true (matching hash with sha256: prefix)")
	}
}

func TestVerifyAgentCard_MismatchingCapabilitiesHash(t *testing.T) {
	cardBody := `{"agentId":"ans-card-001","agentName":"test-agent"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, "deadbeef")
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if result.CapHashValid {
		t.Error("CapHashValid = true, want false (mismatched hash)")
	}
}

func TestVerifyAgentCard_WithVerifiableClaims(t *testing.T) {
	cardBody := `{
		"agentId": "ans-card-001",
		"agentName": "test-agent",
		"verifiableClaims": [
			{"type": "identity", "issuer": "https://ra.example.com"},
			{"type": "certification", "issuer": "https://auditor.example.com"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, "")
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if len(result.ClaimsVerified) != 2 {
		t.Fatalf("ClaimsVerified len = %d, want 2", len(result.ClaimsVerified))
	}

	wantClaims := []struct {
		claimType string
		issuer    string
	}{
		{"identity", "https://ra.example.com"},
		{"certification", "https://auditor.example.com"},
	}
	for i, wc := range wantClaims {
		if result.ClaimsVerified[i].ClaimType != wc.claimType {
			t.Errorf("ClaimsVerified[%d].ClaimType = %q, want %q", i, result.ClaimsVerified[i].ClaimType, wc.claimType)
		}
		if result.ClaimsVerified[i].Issuer != wc.issuer {
			t.Errorf("ClaimsVerified[%d].Issuer = %q, want %q", i, result.ClaimsVerified[i].Issuer, wc.issuer)
		}
		if !result.ClaimsVerified[i].Valid {
			t.Errorf("ClaimsVerified[%d].Valid = false, want true", i)
		}
	}
}

func TestVerifyAgentCard_NoProducerKeys_SignatureInvalid(t *testing.T) {
	cardBody := `{"agentId":"ans-card-001","agentName":"test-agent"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	// nil producerKeys -> SignatureValid stays false.
	v := NewAgentCardVerifier(nil, WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, "")
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if result.SignatureValid {
		t.Error("SignatureValid = true, want false (nil producerKeys)")
	}
}

// --- VerifyAgentCardSignature tests ---

func TestVerifyAgentCardSignature_EmptyPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyAgentCardSignature(nil, &key.PublicKey)
	assertANSErrorCode(t, err, CodeAgentCardSigInvalid)
}

func TestVerifyAgentCardSignature_EmptyBytePayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyAgentCardSignature([]byte{}, &key.PublicKey)
	assertANSErrorCode(t, err, CodeAgentCardSigInvalid)
}

func TestVerifyAgentCardSignature_NilPubKey(t *testing.T) {
	err := VerifyAgentCardSignature([]byte("some payload"), nil)
	assertANSErrorCode(t, err, CodeAgentCardSigInvalid)
}

func TestVerifyAgentCardSignature_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := VerifyAgentCardSignature([]byte("valid-signed-payload"), &key.PublicKey)
	if err != nil {
		t.Errorf("VerifyAgentCardSignature() error = %v, want nil", err)
	}
}

// --- verifyCapabilitiesHash internal tests via VerifyAgentCard ---

func TestVerifyAgentCard_CapabilitiesHashWithComplexCardBody(t *testing.T) {
	// Use a body with nested objects to exercise JCS canonicalization.
	cardBody := `{
		"agentId": "ans-complex-001",
		"agentName": "complex-agent",
		"endpoints": [
			{"protocol": "grpc", "agentUrl": "https://grpc.example.com"}
		]
	}`

	canonical, err := JCSCanonicalize([]byte(cardBody))
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	digest := sha256.Sum256(canonical)
	expectedHash := hex.EncodeToString(digest[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	result, err := v.VerifyAgentCard(context.Background(), server.URL, expectedHash)
	if err != nil {
		t.Fatalf("VerifyAgentCard() error = %v", err)
	}
	if !result.CapHashValid {
		t.Error("CapHashValid = false, want true for complex card body")
	}
}

func TestVerifyAgentCard_Server500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	_, err := v.VerifyAgentCard(context.Background(), server.URL, "")
	if err == nil {
		t.Fatal("VerifyAgentCard() = nil, want error for 500")
	}
	assertANSErrorCode(t, err, CodeAgentCardFetchFailed)
}

func TestVerifyAgentCard_UnreachableServer(t *testing.T) {
	// Create a server then close it immediately to simulate unreachable host.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := server.URL
	server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(&http.Client{Timeout: 2 * time.Second}))
	_, err := v.VerifyAgentCard(context.Background(), addr, "")
	if err == nil {
		t.Fatal("VerifyAgentCard() = nil, want error for unreachable server")
	}
	assertANSErrorCode(t, err, CodeAgentCardFetchFailed)
}

// Ensure the fetch error wraps the underlying cause for debugging.
func TestVerifyAgentCard_FetchErrorWrapsCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewAgentCardVerifier(NewMockProducerKeyLookup(), WithAgentCardHTTPClient(server.Client()))
	_, err := v.VerifyAgentCard(context.Background(), server.URL, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ansErr *ANSError
	if !errors.As(err, &ansErr) {
		t.Fatalf("expected *ANSError, got %T: %v", err, err)
	}
	if ansErr.Cause == nil {
		t.Error("ANSError.Cause is nil, want wrapped cause")
	}
}
