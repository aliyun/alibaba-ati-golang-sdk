package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify/scitt"
)

// testScittKeyBundle holds a generated ECDSA key with its derived kid.
type testScittKeyBundle struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	kid  [4]byte
	name string
}

func generateScittTestKey(t *testing.T, name string) *testScittKeyBundle {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	hash := sha256.Sum256(spkiDer)
	var kid [4]byte
	copy(kid[:], hash[:4])
	return &testScittKeyBundle{priv: priv, pub: &priv.PublicKey, kid: kid, name: name}
}

// testKeyLookup implements scitt.KeyLookup for tests.
type testKeyLookup struct {
	keys map[[4]byte]*scitt.TrustedKey
}

func (s *testKeyLookup) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	tk, ok := s.keys[kid]
	if !ok {
		return nil, &scitt.SignatureError{
			Type:    scitt.SigErrUnknownKeyID,
			Kid:     kid,
			Message: "unknown key ID in test",
		}
	}
	return tk, nil
}

func newTestScittKeyLookup(bundles ...*testScittKeyBundle) *testKeyLookup {
	keys := make(map[[4]byte]*scitt.TrustedKey, len(bundles))
	for _, b := range bundles {
		keys[b.kid] = &scitt.TrustedKey{
			Name: b.name,
			Kid:  b.kid,
			Key:  b.pub,
		}
	}
	return &testKeyLookup{keys: keys}
}

// signP1363ForTest signs a SHA-256 digest with P1363 format (64 bytes).
func signP1363ForTest(t *testing.T, priv *ecdsa.PrivateKey, digest [32]byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig
}

// buildTestReceipt builds a valid COSE_Sign1 receipt with VDP.
func buildTestReceipt(t *testing.T, bundle *testScittKeyBundle, payload []byte) []byte {
	t.Helper()

	// Protected header: alg=ES256, kid, vds=1
	hdr := map[int64]interface{}{
		1:   int64(-7),     // alg = ES256
		4:   bundle.kid[:], // kid
		395: int64(1),      // vds = RFC 9162
	}
	protectedBytes, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}

	digest, err := scitt.ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}

	sig := signP1363ForTest(t, bundle.priv, digest)

	// Unprotected with VDP: tree_size=1, leaf_index=0, no inclusion path
	vdp := map[int64]interface{}{
		int64(-1): uint64(1), // tree_size
		int64(-2): uint64(0), // leaf_index
	}
	unprotected, err := cbor.Marshal(map[int64]interface{}{
		int64(396): vdp,
	})
	if err != nil {
		t.Fatalf("marshal unprotected: %v", err)
	}

	// COSE_Sign1 array: [protected, unprotected, payload, signature]
	protEnc, _ := cbor.Marshal(protectedBytes)
	payEnc, _ := cbor.Marshal(payload)
	sigEnc, _ := cbor.Marshal(sig)

	arr := []cbor.RawMessage{protEnc, cbor.RawMessage(unprotected), payEnc, sigEnc}
	arrayBytes, err := cbor.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal array: %v", err)
	}

	tag := cbor.RawTag{Number: 18, Content: arrayBytes}
	tagged, err := tag.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal tag: %v", err)
	}
	return tagged
}

// buildTestStatusToken builds a valid COSE_Sign1 status token.
func buildTestStatusToken(t *testing.T, bundle *testScittKeyBundle, agentID, atiName string, status scitt.AgentStatus, iat, exp int64, serverCerts, identityCerts [][32]byte) []byte {
	t.Helper()

	// Build CBOR payload map
	m := make(map[interface{}]interface{})
	m[int64(1)] = agentID
	m[int64(2)] = string(status)
	m[int64(3)] = iat
	m[int64(4)] = exp
	m[int64(5)] = atiName

	if identityCerts != nil {
		certs := make([]map[interface{}]interface{}, 0, len(identityCerts))
		for _, fp := range identityCerts {
			certs = append(certs, map[interface{}]interface{}{
				"fingerprint": fp[:],
				"cert_type":   "x509-ov-client",
			})
		}
		m[int64(6)] = certs
	}
	if serverCerts != nil {
		certs := make([]map[interface{}]interface{}, 0, len(serverCerts))
		for _, fp := range serverCerts {
			certs = append(certs, map[interface{}]interface{}{
				"fingerprint": fp[:],
				"cert_type":   "x509-dv-server",
			})
		}
		m[int64(7)] = certs
	}

	payload, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("marshal status payload: %v", err)
	}

	// Protected header (no vds for status token)
	hdr := map[int64]interface{}{
		1: int64(-7),     // alg = ES256
		4: bundle.kid[:], // kid
	}
	protectedBytes, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}

	digest, err := scitt.ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}

	sig := signP1363ForTest(t, bundle.priv, digest)

	// Unprotected: empty map
	unprotected, _ := cbor.Marshal(map[int64]interface{}{})

	protEnc, _ := cbor.Marshal(protectedBytes)
	payEnc, _ := cbor.Marshal(payload)
	sigEnc, _ := cbor.Marshal(sig)

	arr := []cbor.RawMessage{protEnc, cbor.RawMessage(unprotected), payEnc, sigEnc}
	arrayBytes, err := cbor.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal array: %v", err)
	}

	tag := cbor.RawTag{Number: 18, Content: arrayBytes}
	tagged, err := tag.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal tag: %v", err)
	}
	return tagged
}

func TestVerifyWithHeaders_FullScittSuccess_ServerRole(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	var fpBytes [32]byte
	decoded, _ := hex.DecodeString(fpHex)
	copy(fpBytes[:], decoded)

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	atiName := "ati://v1.0.0." + host

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.StatusActive,
		now-60, now+3600, [][32]byte{fpBytes}, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver()),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	if outcome.Type != OutcomeVerified {
		t.Fatalf("Type = %v, want OutcomeVerified (error: %v)", outcome.Type, outcome.Error)
	}
	if outcome.Tier != TierFullScitt {
		t.Errorf("Tier = %v, want TierFullScitt", outcome.Tier)
	}
	if outcome.MatchedFingerprint == nil {
		t.Error("MatchedFingerprint should not be nil")
	}
}

func TestVerifyWithHeaders_FullScittSuccess_IdentityRole(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	var fpBytes [32]byte
	decoded, _ := hex.DecodeString(fpHex)
	copy(fpBytes[:], decoded)

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	atiName := "ati://v1.0.0." + host

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.StatusActive,
		now-60, now+3600, nil, [][32]byte{fpBytes})

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	badgeURL := "https://tlog.example.com/v1/agents/test-id"
	badge := createTestTLResponse(host, "v1.0.0", fingerprint, fingerprint)
	dnsRecord := ATIBadgeRecord{
		FormatVersion: "ati-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver().WithRecords(host, []ATIBadgeRecord{dnsRecord})),
		WithTlogClient(NewMockTransparencyLogClient().WithTLResponse(badgeURL, badge)),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewClientVerifier(opts...)
	cert := createMTLSCertIdentity(host, "v1.0.0", fingerprint)
	outcome := verifier.VerifyWithScitt(context.Background(), cert, headers)

	if outcome.Type != OutcomeVerified {
		t.Fatalf("Type = %v, want OutcomeVerified (error: %v)", outcome.Type, outcome.Error)
	}
	if outcome.Tier != TierFullScitt {
		t.Errorf("Tier = %v, want TierFullScitt", outcome.Tier)
	}
}

func TestVerifyWithHeaders_StatusNotValidForConnection(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	var fpBytes [32]byte
	decoded, _ := hex.DecodeString(fpHex)
	copy(fpBytes[:], decoded)

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	atiName := "ati://v1.0.0." + host

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	// Use EXPIRED status which is valid (not terminal in VerifyStatusToken)
	// but IsValidForConnection returns false
	// Actually EXPIRED is terminal and would be rejected by VerifyStatusToken...
	// Let's use a custom invalid status that passes VerifyStatusToken but fails IsValidForConnection
	// Actually looking at the code, StatusExpired IS terminal and gets rejected at step 7.
	// So we need a status that passes IsTerminal=false but fails IsValidForConnection=false
	// Looking at types.go: ACTIVE/WARNING/DEPRECATED pass both; EXPIRED/REVOKED are terminal.
	// Any OTHER status passes IsTerminal=false but fails IsValidForConnection=false.
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.AgentStatus("SUSPENDED"),
		now-60, now+3600, [][32]byte{fpBytes}, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver()),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	if outcome.Type != OutcomeScittError {
		t.Fatalf("Type = %v, want OutcomeScittError (error: %v)", outcome.Type, outcome.Error)
	}
	if outcome.Error == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestVerifyWithHeaders_FingerprintMismatch(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	// Different fingerprint in the status token
	var differentFP [32]byte
	differentFP[0] = 0xFF

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	atiName := "ati://v1.0.0." + host

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.StatusActive,
		now-60, now+3600, [][32]byte{differentFP}, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver()),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	if outcome.Type != OutcomeScittError {
		t.Fatalf("Type = %v, want OutcomeScittError", outcome.Type)
	}
	if outcome.Error == nil || !contains(outcome.Error.Error(), "fingerprint") {
		t.Errorf("expected fingerprint mismatch error, got: %v", outcome.Error)
	}
}

func TestVerifyWithHeaders_ATINameHostMismatch(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	var fpBytes [32]byte
	decoded, _ := hex.DecodeString(fpHex)
	copy(fpBytes[:], decoded)

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	// ATIName host does NOT match the requested fqdn
	atiName := "ati://v1.0.0.different.example.com"

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.StatusActive,
		now-60, now+3600, [][32]byte{fpBytes}, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver()),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	if outcome.Type != OutcomeScittError {
		t.Fatalf("Type = %v, want OutcomeScittError", outcome.Type)
	}
	if outcome.Error == nil || !contains(outcome.Error.Error(), "does not match") {
		t.Errorf("expected ATIName host mismatch error, got: %v", outcome.Error)
	}
}

func TestVerifyWithHeaders_DeprecatedStatusWarning(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	var fpBytes [32]byte
	decoded, _ := hex.DecodeString(fpHex)
	copy(fpBytes[:], decoded)

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	atiName := "ati://v1.0.0." + host

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.StatusDeprecated,
		now-60, now+3600, [][32]byte{fpBytes}, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver()),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	if outcome.Type != OutcomeVerified {
		t.Fatalf("Type = %v, want OutcomeVerified (error: %v)", outcome.Type, outcome.Error)
	}
	if outcome.Tier != TierFullScitt {
		t.Errorf("Tier = %v, want TierFullScitt", outcome.Tier)
	}
	// Check that deprecated status produces a warning
	if len(outcome.Warnings) == 0 {
		t.Error("expected at least one warning for DEPRECATED status")
	}
	found := false
	for _, w := range outcome.Warnings {
		if contains(w, "DEPRECATED") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DEPRECATED warning, got: %v", outcome.Warnings)
	}
}

func TestVerifyWithHeaders_TokenTransportErrorFallback(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	bundle := generateScittTestKey(t, "test-issuer")

	badgeURL := "https://tlog.example.com/v1/agents/test-id"
	badge := createTestTLResponse(host, "v1.0.0", fingerprint, "SHA256:aaa")
	dnsRecord := ATIBadgeRecord{
		FormatVersion: "ati-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	// Build a valid receipt (passes receipt verification)
	receipt := buildTestReceipt(t, bundle, []byte("event"))

	// Build a token that will trigger a transport error during key lookup
	// Use a different kid so the key lookup returns transport error
	otherBundle := generateScittTestKey(t, "other-key")
	now := time.Now().Unix()
	token := buildTestStatusToken(t, otherBundle, "agent-1", "ati://v1.0.0."+host,
		scitt.StatusActive, now-60, now+3600, nil, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	// Use a key lookup that returns transport error for unknown keys
	lookup := &transportErrorKeyLookup{errType: scitt.TransportErrHTTPError}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver().WithRecords(host, []ATIBadgeRecord{dnsRecord})),
		WithTlogClient(NewMockTransparencyLogClient().WithTLResponse(badgeURL, badge)),
		WithScittKeyLookup(lookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	// Should fall back to badge verification
	if outcome.Type != OutcomeVerified {
		t.Fatalf("Type = %v, want OutcomeVerified (fallback to badge), error: %v", outcome.Type, outcome.Error)
	}
	if outcome.Tier != TierBadgeOnly {
		t.Errorf("Tier = %v, want TierBadgeOnly (fallback)", outcome.Tier)
	}
}

func TestVerifyWithHeaders_InvalidATINameInToken(t *testing.T) {
	host := "test.example.com"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fingerprint := "SHA256:" + fpHex

	var fpBytes [32]byte
	decoded, _ := hex.DecodeString(fpHex)
	copy(fpBytes[:], decoded)

	bundle := generateScittTestKey(t, "test-issuer")
	keyLookup := newTestScittKeyLookup(bundle)

	now := time.Now().Unix()
	// Invalid ATI name format
	atiName := "not-a-valid-ati-name"

	receipt := buildTestReceipt(t, bundle, []byte("receipt-event"))
	token := buildTestStatusToken(t, bundle, "agent-1", atiName, scitt.StatusActive,
		now-60, now+3600, [][32]byte{fpBytes}, nil)

	headers := &scitt.Headers{
		Receipt:     receipt,
		StatusToken: token,
	}

	opts := []Option{
		WithDNSResolver(NewMockDNSResolver()),
		WithScittKeyLookup(keyLookup),
		WithoutURLValidation(),
	}

	verifier := NewServerVerifier(opts...)
	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)

	if outcome.Type != OutcomeScittError {
		t.Fatalf("Type = %v, want OutcomeScittError", outcome.Type)
	}
	if outcome.Error == nil || !contains(outcome.Error.Error(), "invalid ATIName") {
		t.Errorf("expected invalid ATIName error, got: %v", outcome.Error)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
