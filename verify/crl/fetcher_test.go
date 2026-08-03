package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewFetcher_Default(t *testing.T) {
	f := NewFetcher()
	if f == nil {
		t.Fatal("NewFetcher() returned nil")
	}
	if f.maxAge != defaultMaxAge {
		t.Errorf("maxAge = %v, want %v", f.maxAge, defaultMaxAge)
	}
	if f.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if f.cache == nil {
		t.Error("cache is nil")
	}
}

func TestNewFetcher_WithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	f := NewFetcher(WithHTTPClient(customClient))
	if f.httpClient != customClient {
		t.Error("httpClient was not set by WithHTTPClient")
	}
}

func TestNewFetcher_WithMaxAge(t *testing.T) {
	f := NewFetcher(WithMaxAge(1 * time.Hour))
	if f.maxAge != 1*time.Hour {
		t.Errorf("maxAge = %v, want 1h", f.maxAge)
	}
}

func TestFetcher_Fetch_Success(t *testing.T) {
	ca, caKey := generateFetcherTestCA(t)
	crlBytes := generateFetcherTestCRL(t, ca, caKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/pkix-crl" {
			t.Errorf("Accept header = %q, want application/pkix-crl", r.Header.Get("Accept"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()), WithAllowPrivateNetworks(true))
	data, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(data) == 0 {
		t.Error("Fetch() returned empty data")
	}
}

func TestFetcher_Fetch_Caching(t *testing.T) {
	ca, caKey := generateFetcherTestCA(t)
	crlBytes := generateFetcherTestCRL(t, ca, caKey)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()), WithMaxAge(1*time.Hour), WithAllowPrivateNetworks(true))

	// First fetch
	_, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}

	// Second fetch should use cache
	_, err = f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}

	if callCount != 1 {
		t.Errorf("server called %d times, want 1 (cached)", callCount)
	}
}

func TestFetcher_Fetch_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()), WithAllowPrivateNetworks(true))
	_, err := f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestFetcher_Fetch_InvalidURI(t *testing.T) {
	f := NewFetcher()
	_, err := f.Fetch(context.Background(), "://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URI, got nil")
	}
}

func TestFetcher_Fetch_ConnectionError(t *testing.T) {
	f := NewFetcher(WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}))
	_, err := f.Fetch(context.Background(), "http://192.0.2.1:1/unreachable.crl")
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestFetcher_Fetch_NonParsableCRL_StillCached(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not a valid CRL but still bytes"))
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()), WithAllowPrivateNetworks(true))
	data, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch() error = %v (should succeed even with non-parsable CRL body)", err)
	}
	if string(data) != "not a valid CRL but still bytes" {
		t.Errorf("got %q", string(data))
	}
}

func TestFetcher_Fetch_SSRFGuard_BlocksLoopbackByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be invoked; SSRF guard must reject before the request is sent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// No WithAllowPrivateNetworks(true) — guard is on by default, and the
	// httptest server listens on a loopback address.
	f := NewFetcher(WithHTTPClient(server.Client()))
	_, err := f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected SSRF guard to reject a loopback CDP URI, got nil error")
	}
}

func TestFetcher_Fetch_SSRFGuard_AllowPrivateNetworksOverride(t *testing.T) {
	ca, caKey := generateFetcherTestCA(t)
	crlBytes := generateFetcherTestCRL(t, ca, caKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlBytes)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()), WithAllowPrivateNetworks(true))
	if _, err := f.Fetch(context.Background(), server.URL); err != nil {
		t.Fatalf("Fetch() with WithAllowPrivateNetworks(true) error = %v", err)
	}
}

func TestFetcher_Fetch_ResponseTooLarge(t *testing.T) {
	oversized := make([]byte, maxCRLBodySize+1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(oversized)
	}))
	defer server.Close()

	f := NewFetcher(WithHTTPClient(server.Client()), WithAllowPrivateNetworks(true))
	_, err := f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for oversized CRL response, got nil")
	}
}

func TestFetcher_Fetch_ExpiredNextUpdate_ForcesImmediateRefetch(t *testing.T) {
	ca, caKey := generateFetcherTestCA(t)
	// NextUpdate is already in the past: the CRL is stale on arrival.
	crlBytes := generateFetcherTestCRLWithNextUpdate(t, ca, caKey, time.Now().Add(-1*time.Hour))

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write(crlBytes)
	}))
	defer server.Close()

	// A long maxAge would previously mask the bug: an expired CRL fell back
	// to caching for defaultMaxAge instead of ttl=0.
	f := NewFetcher(WithHTTPClient(server.Client()), WithMaxAge(12*time.Hour), WithAllowPrivateNetworks(true))

	if _, err := f.Fetch(context.Background(), server.URL); err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}
	if _, err := f.Fetch(context.Background(), server.URL); err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}

	if callCount != 2 {
		t.Errorf("server called %d times, want 2 (expired CRL must not be cached for maxAge)", callCount)
	}
}

func TestCachedEntry_IsExpired(t *testing.T) {
	entry := &cachedEntry{
		data:      []byte("test"),
		fetchedAt: time.Now().Add(-2 * time.Hour),
		ttl:       1 * time.Hour,
	}
	if !entry.isExpired() {
		t.Error("entry should be expired")
	}

	entry.fetchedAt = time.Now()
	if entry.isExpired() {
		t.Error("entry should not be expired")
	}
}

func generateFetcherTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Fetcher Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	return cert, key
}

func generateFetcherTestCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	return generateFetcherTestCRLWithNextUpdate(t, issuer, issuerKey, time.Now().Add(24*time.Hour))
}

func generateFetcherTestCRLWithNextUpdate(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, nextUpdate time.Time) []byte {
	t.Helper()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: nextUpdate.Add(-1 * time.Hour),
		NextUpdate: nextUpdate,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlBytes
}
