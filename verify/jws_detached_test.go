package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestJWSDetached_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	payload := []byte(`{"action":"transfer","amount":100}`)

	sig, err := CreateJWSDetached(payload, key, "tx-key-1")
	if err != nil {
		t.Fatalf("CreateJWSDetached() = %v", err)
	}

	keys := NewMockProducerKeyLookup().WithKey("tx-key-1", &key.PublicKey)

	if err := VerifyJWSDetached(sig, payload, keys); err != nil {
		t.Errorf("VerifyJWSDetached() = %v, want nil", err)
	}
}

func TestJWSDetached_TamperedPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"action":"transfer","amount":100}`)

	sig, _ := CreateJWSDetached(payload, key, "tx-key-1")

	keys := NewMockProducerKeyLookup().WithKey("tx-key-1", &key.PublicKey)

	tampered := []byte(`{"action":"transfer","amount":999}`)
	if err := VerifyJWSDetached(sig, tampered, keys); err == nil {
		t.Error("VerifyJWSDetached() = nil, want error for tampered payload")
	}
}

func TestJWSDetached_WrongKey(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`test payload`)

	sig, _ := CreateJWSDetached(payload, key1, "key-1")

	keys := NewMockProducerKeyLookup().WithKey("key-1", &key2.PublicKey)

	if err := VerifyJWSDetached(sig, payload, keys); err == nil {
		t.Error("VerifyJWSDetached() = nil, want error for wrong key")
	}
}

func TestJWSDetached_InvalidFormat(t *testing.T) {
	keys := NewMockProducerKeyLookup()

	tests := []struct {
		name string
		sig  string
	}{
		{"no parts", "invalid"},
		{"one part", "header."},
		{"non-empty payload", "aGVhZGVy.cGF5bG9hZA.c2ln"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyJWSDetached(tt.sig, []byte("test"), keys); err == nil {
				t.Error("VerifyJWSDetached() = nil, want error")
			}
		})
	}
}

func TestJWSDetached_MissingKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`test`)

	sig, _ := CreateJWSDetached(payload, key, "existing-kid")

	keys := NewMockProducerKeyLookup() // no keys registered

	if err := VerifyJWSDetached(sig, payload, keys); err == nil {
		t.Error("VerifyJWSDetached() = nil, want error for missing key")
	}
}

func TestCreateJWSDetached_WrongCurve(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	_, err := CreateJWSDetached([]byte("test"), key, "kid")
	if err == nil {
		t.Error("CreateJWSDetached() = nil, want error for P-384 key")
	}
}
