package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// makeStaplingCredJSON builds a JSON stapled credential for testing.
func makeStaplingCredJSON(t *testing.T, ansID, status, signature string, issuedAt, expiresAt time.Time) []byte {
	t.Helper()
	cred := StapledCredential{
		AnsID:     ansID,
		Status:    status,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Signature: signature,
		Kid:       "test-kid",
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("failed to marshal credential: %v", err)
	}
	return raw
}

// computeTestStaplingDigest mirrors computeStaplingDigest for test setup.
func computeTestStaplingDigest(t *testing.T, cred *StapledCredential) [32]byte {
	t.Helper()
	payload := struct {
		AnsID     string `json:"ansId"`
		Status    string `json:"status"`
		IssuedAt  string `json:"issuedAt"`
		ExpiresAt string `json:"expiresAt"`
	}{
		AnsID:     cred.AnsID,
		Status:    cred.Status,
		IssuedAt:  cred.IssuedAt.Format(time.RFC3339),
		ExpiresAt: cred.ExpiresAt.Format(time.RFC3339),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	canonical, err := JCSCanonicalize(payloadJSON)
	if err != nil {
		t.Fatalf("JCS canonicalization failed: %v", err)
	}
	return sha256.Sum256(canonical)
}

// signTestStaplingCredential signs the credential digest with the given key
// and returns the base64-encoded signature.
func signTestStaplingCredential(t *testing.T, cred *StapledCredential, key *ecdsa.PrivateKey) string {
	t.Helper()
	digest := computeTestStaplingDigest(t, cred)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("failed to sign stapling credential: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// assertANSErrorCode checks that err is an *ANSError with the expected code.
func assertANSErrorCode(t *testing.T, err error, expectedCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", expectedCode)
	}
	var ansErr *ANSError
	if !errors.As(err, &ansErr) {
		t.Fatalf("expected *ANSError, got %T: %v", err, err)
	}
	if ansErr.Code != expectedCode {
		t.Fatalf("error code = %q, want %q (message: %s)", ansErr.Code, expectedCode, ansErr.Message)
	}
}

// --- ParseStapledCredential tests ---

func TestParseStapledCredential_Valid(t *testing.T) {
	now := time.Now().UTC()
	raw := makeStaplingCredJSON(t, "ans-001", "ACTIVE", "sig-abc", now.Add(-1*time.Hour), now.Add(1*time.Hour))

	cred, err := ParseStapledCredential(raw)
	if err != nil {
		t.Fatalf("ParseStapledCredential() error = %v", err)
	}
	if cred.AnsID != "ans-001" {
		t.Errorf("AnsID = %q, want %q", cred.AnsID, "ans-001")
	}
	if cred.Status != "ACTIVE" {
		t.Errorf("Status = %q, want %q", cred.Status, "ACTIVE")
	}
	if cred.Signature != "sig-abc" {
		t.Errorf("Signature = %q, want %q", cred.Signature, "sig-abc")
	}
	if cred.Kid != "test-kid" {
		t.Errorf("Kid = %q, want %q", cred.Kid, "test-kid")
	}
}

func TestParseStapledCredential_InvalidJSON(t *testing.T) {
	_, err := ParseStapledCredential([]byte(`{invalid json`))
	if err == nil {
		t.Fatal("ParseStapledCredential() = nil, want error for invalid JSON")
	}
}

func TestParseStapledCredential_MissingAnsID(t *testing.T) {
	now := time.Now().UTC()
	raw := []byte(`{"status":"ACTIVE","issuedAt":"` + now.Format(time.RFC3339) + `","expiresAt":"` + now.Format(time.RFC3339) + `","signature":"sig","kid":"k1"}`)
	_, err := ParseStapledCredential(raw)
	if err == nil {
		t.Fatal("ParseStapledCredential() = nil, want error for missing ansId")
	}
}

func TestParseStapledCredential_MissingStatus(t *testing.T) {
	now := time.Now().UTC()
	raw := []byte(`{"ansId":"ans-001","issuedAt":"` + now.Format(time.RFC3339) + `","expiresAt":"` + now.Format(time.RFC3339) + `","signature":"sig","kid":"k1"}`)
	_, err := ParseStapledCredential(raw)
	if err == nil {
		t.Fatal("ParseStapledCredential() = nil, want error for missing status")
	}
}

func TestParseStapledCredential_MissingSignature(t *testing.T) {
	now := time.Now().UTC()
	raw := []byte(`{"ansId":"ans-001","status":"ACTIVE","issuedAt":"` + now.Format(time.RFC3339) + `","expiresAt":"` + now.Format(time.RFC3339) + `","kid":"k1"}`)
	_, err := ParseStapledCredential(raw)
	if err == nil {
		t.Fatal("ParseStapledCredential() = nil, want error for missing signature")
	}
}

// --- VerifyStapledCredential tests ---

func TestVerifyStapledCredential_NilCredential(t *testing.T) {
	err := VerifyStapledCredential(nil, NewMockProducerKeyLookup(), time.Now())
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_Expired(t *testing.T) {
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour), // already expired
		Signature: "sig",
		Kid:       "test-kid",
	}
	err := VerifyStapledCredential(cred, NewMockProducerKeyLookup(), now)
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_IssuedAtInFuture(t *testing.T) {
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(1 * time.Hour), // future
		ExpiresAt: now.Add(2 * time.Hour),
		Signature: "sig",
		Kid:       "test-kid",
	}
	err := VerifyStapledCredential(cred, NewMockProducerKeyLookup(), now)
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_StatusRevoked(t *testing.T) {
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "REVOKED",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Signature: "sig",
		Kid:       "test-kid",
	}
	err := VerifyStapledCredential(cred, NewMockProducerKeyLookup(), now)
	assertANSErrorCode(t, err, CodeStatusRevoked)
}

func TestVerifyStapledCredential_StatusExpired(t *testing.T) {
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "EXPIRED",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Signature: "sig",
		Kid:       "test-kid",
	}
	err := VerifyStapledCredential(cred, NewMockProducerKeyLookup(), now)
	assertANSErrorCode(t, err, CodeStatusRevoked)
}

func TestVerifyStapledCredential_NilKeyLookup(t *testing.T) {
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Signature: "sig",
		Kid:       "test-kid",
	}
	err := VerifyStapledCredential(cred, nil, now)
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_KeyNotFound(t *testing.T) {
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Signature: "sig",
		Kid:       "missing-kid",
	}
	// Mock with no keys registered for "missing-kid"
	err := VerifyStapledCredential(cred, NewMockProducerKeyLookup(), now)
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_InvalidBase64Signature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Signature: "!!!not-valid-base64!!!",
		Kid:       "test-kid",
	}
	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)
	err = VerifyStapledCredential(cred, keys, now)
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_SignatureVerificationFails(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	now := time.Now().UTC()
	// A valid base64 string that decodes but is not a valid signature for this credential
	bogusSig := base64.StdEncoding.EncodeToString([]byte("not-a-real-signature-but-valid-base64"))
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Signature: bogusSig,
		Kid:       "test-kid",
	}
	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)
	err = VerifyStapledCredential(cred, keys, now)
	assertANSErrorCode(t, err, CodeStaplingExpired)
}

func TestVerifyStapledCredential_ValidSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	now := time.Now().UTC()
	cred := &StapledCredential{
		AnsID:     "ans-001",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(1 * time.Hour),
		Kid:       "test-kid",
	}
	cred.Signature = signTestStaplingCredential(t, cred, key)

	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)
	if err := VerifyStapledCredential(cred, keys, now); err != nil {
		t.Errorf("VerifyStapledCredential() error = %v, want nil", err)
	}
}

func TestVerifyStapledCredential_ValidSignatureAtExpiryBoundary(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	now := time.Now().UTC()
	// ExpiresAt == now: now.After(ExpiresAt) is false, so it should still be valid.
	cred := &StapledCredential{
		AnsID:     "ans-boundary",
		Status:    "ACTIVE",
		IssuedAt:  now.Add(-1 * time.Hour),
		ExpiresAt: now,
		Kid:       "test-kid",
	}
	cred.Signature = signTestStaplingCredential(t, cred, key)

	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)
	if err := VerifyStapledCredential(cred, keys, now); err != nil {
		t.Errorf("VerifyStapledCredential() at expiry boundary error = %v, want nil", err)
	}
}

func TestVerifyStapledCredential_ValidSignatureAtIssuedAtBoundary(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	now := time.Now().UTC()
	// IssuedAt == now: now.Before(IssuedAt) is false, so it should still be valid.
	cred := &StapledCredential{
		AnsID:     "ans-issued-boundary",
		Status:    "ACTIVE",
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
		Kid:       "test-kid",
	}
	cred.Signature = signTestStaplingCredential(t, cred, key)

	keys := NewMockProducerKeyLookup().WithKey("test-kid", &key.PublicKey)
	if err := VerifyStapledCredential(cred, keys, now); err != nil {
		t.Errorf("VerifyStapledCredential() at issuedAt boundary error = %v, want nil", err)
	}
}

func TestComputeStaplingDigest_MatchesExpectedFormat(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cred := &StapledCredential{
		AnsID:     "ans-digest",
		Status:    "ACTIVE",
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	}
	digest, err := computeStaplingDigest(cred)
	if err != nil {
		t.Fatalf("computeStaplingDigest() error = %v", err)
	}

	// Independently compute the expected digest.
	payload := struct {
		AnsID     string `json:"ansId"`
		Status    string `json:"status"`
		IssuedAt  string `json:"issuedAt"`
		ExpiresAt string `json:"expiresAt"`
	}{
		AnsID:     cred.AnsID,
		Status:    cred.Status,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(1 * time.Hour).Format(time.RFC3339),
	}
	payloadJSON, _ := json.Marshal(payload)
	canonical, err := JCSCanonicalize(payloadJSON)
	if err != nil {
		t.Fatalf("JCSCanonicalize() error = %v", err)
	}
	expected := sha256.Sum256(canonical)

	if digest != expected {
		t.Errorf("computeStaplingDigest() = %x, want %x", digest, expected)
	}
}
