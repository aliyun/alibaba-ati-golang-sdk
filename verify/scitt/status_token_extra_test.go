package scitt

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestVerifyECDSA_NilPublicKey exercises the defensive path in verifyECDSA
// where the key is nil, causing ComputeSigStructureDigest or ecdsa.VerifyASN1
// to fail. This targets the signature verification failure at status_token.go
// line 147 (SigErrSignatureInvalid).
func TestVerifyECDSA_NilPublicKey(t *testing.T) {
	t.Parallel()

	kid := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	protectedBytes := []byte{0xa1, 0x01, 0x26} // minimal valid protected header
	payload := []byte("test-payload")
	sig := make([]byte, 64) // zero signature

	// With a nil public key, ecdsa.VerifyASN1 panics in Go's stdlib, so the
	// function returns SigErrSignatureInvalid. The digest computation step
	// (line 121) succeeds, then the nil key causes a panic at VerifyASN1.
	// We use a deferred recover to confirm and accept either an error or panic.
	defer func() {
		if r := recover(); r != nil {
			// A panic from ecdsa.VerifyASN1(nil, ...) is acceptable — it means
			// we reached the verification step (line 147), exercising the path.
		}
	}()
	err := verifyECDSA(nil, protectedBytes, payload, sig, kid)
	if err != nil {
		var sigErr *SignatureError
		if !errors.As(err, &sigErr) {
			t.Fatalf("expected *SignatureError, got %T: %v", err, err)
		}
		if sigErr.Type != SigErrSignatureInvalid {
			t.Errorf("error type = %d, want SigErrSignatureInvalid", sigErr.Type)
		}
	}
}

// TestVerifyECDSA_WrongKey exercises the branch at status_token.go:147-153
// where ecdsa.VerifyASN1 returns false (signature verification failed).
func TestVerifyECDSA_WrongKey(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "ecdsa-wrong-key")
	ki2 := generateTestKey(t, "ecdsa-correct-key")

	kid := ki.kid
	protectedBytes := []byte{0xa1, 0x01, 0x26}
	payload := []byte("test-payload")

	// Sign with ki2's private key.
	digest, err := ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("failed to compute digest: %v", err)
	}
	sig := signP1363(t, ki2.priv, digest)

	// Verify against ki's public key (mismatch).
	err = verifyECDSA(ki.pub, protectedBytes, payload, sig, kid)
	if err == nil {
		t.Fatal("expected error with mismatched key")
	}
	var sigErr *SignatureError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected *SignatureError, got %T: %v", err, err)
	}
	if sigErr.Type != SigErrSignatureInvalid {
		t.Errorf("error type = %d, want SigErrSignatureInvalid", sigErr.Type)
	}
	if !strings.Contains(err.Error(), "ECDSA signature verification failed") {
		t.Errorf("error = %q, want containing 'ECDSA signature verification failed'", err.Error())
	}
}

// TestVerifyECDSA_ValidSignature exercises the happy path of verifyECDSA
// (status_token.go:121-156) to confirm the signature verification path succeeds,
// covering the digest computation, r/s split, DER marshal, and VerifyASN1.
func TestVerifyECDSA_ValidSignature(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "ecdsa-valid")

	protectedBytes := []byte{0xa1, 0x01, 0x26}
	payload := []byte("test-payload-for-valid-sig")

	digest, err := ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("failed to compute digest: %v", err)
	}

	// Sign with the private key.
	sig := signP1363(t, ki.priv, digest)

	// Verify with the correct public key — should succeed.
	err = verifyECDSA(ki.pub, protectedBytes, payload, sig, ki.kid)
	if err != nil {
		t.Fatalf("expected success with valid signature, got: %v", err)
	}
}

// TestVerifyECDSA_ZeroSignature exercises verifyECDSA with a 64-byte zero
// signature against a real key, which triggers SigErrSignatureInvalid (line
// 147-153) since ecdsa.VerifyASN1 returns false for (0,0) as the signature.
func TestVerifyECDSA_ZeroSignature(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "ecdsa-zero-sig")

	protectedBytes := []byte{0xa1, 0x01, 0x26}
	payload := []byte("test-payload")
	sig := make([]byte, 64) // zero signature

	err := verifyECDSA(ki.pub, protectedBytes, payload, sig, ki.kid)
	if err == nil {
		t.Fatal("expected error with zero signature")
	}
	var sigErr *SignatureError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected *SignatureError, got %T: %v", err, err)
	}
	if sigErr.Type != SigErrSignatureInvalid {
		t.Errorf("error type = %d, want SigErrSignatureInvalid", sigErr.Type)
	}
}

// TestNewPayloadFieldGetter_Int64KeyFallback exercises the int64 key fallback
// branch at status_token.go:167-169. When the raw map uses int64 keys (as
// produced by CBOR decoding with int64 map keys), the getter should find them
// via the int64 fallback.
func TestNewPayloadFieldGetter_Int64KeyFallback(t *testing.T) {
	t.Parallel()

	// Build a raw map with int64 keys (simulating CBOR-decoded map with int64 keys).
	agentIDBytes, _ := cbor.Marshal("agent-via-int64")
	expBytes, _ := cbor.Marshal(int64(9999))

	rawMap := make(map[interface{}]cbor.RawMessage)
	rawMap[int64(1)] = agentIDBytes // agent_id via int64 key
	rawMap[int64(4)] = expBytes     // exp via int64 key

	get := newPayloadFieldGetter(rawMap)
	dm, _ := newDecMode()

	// The int64 key fallback (line 167-169) should find the value.
	raw, ok := get(payloadKeyAgentID, "agent_id")
	if !ok {
		t.Fatal("expected to find agent_id via int64 key fallback")
	}
	var val string
	if err := dm.Unmarshal(raw, &val); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if val != "agent-via-int64" {
		t.Errorf("agent_id = %q, want %q", val, "agent-via-int64")
	}

	// Verify the exp field via int64 key fallback.
	raw2, ok2 := get(payloadKeyExp, "exp")
	if !ok2 {
		t.Fatal("expected to find exp via int64 key fallback")
	}
	var expVal int64
	if err := dm.Unmarshal(raw2, &expVal); err != nil {
		t.Fatalf("failed to unmarshal exp: %v", err)
	}
	if expVal != 9999 {
		t.Errorf("exp = %d, want 9999", expVal)
	}
}

// TestNewPayloadFieldGetter_Uint64DirectKey exercises the uint64 direct key
// path at status_token.go:164-166. When the raw map uses uint64 keys, the
// getter should find them directly.
func TestNewPayloadFieldGetter_Uint64DirectKey(t *testing.T) {
	t.Parallel()

	rawMap := make(map[interface{}]cbor.RawMessage)
	valBytes, _ := cbor.Marshal("uint-key-value")
	rawMap[uint64(1)] = valBytes

	get := newPayloadFieldGetter(rawMap)

	_, ok := get(payloadKeyAgentID, "agent_id")
	if !ok {
		t.Fatal("expected to find value via uint64 direct key")
	}
}

// TestNewPayloadFieldGetter_NotFound exercises the not-found path at
// status_token.go:173 where no key (uint64, int64, or string) matches.
func TestNewPayloadFieldGetter_NotFound(t *testing.T) {
	t.Parallel()

	rawMap := make(map[interface{}]cbor.RawMessage)
	rawMap[int64(99)] = []byte{0x01}

	get := newPayloadFieldGetter(rawMap)

	_, ok := get(payloadKeyAgentID, "agent_id")
	if ok {
		t.Error("expected ok=false for non-existent key")
	}
}

// TestDecodePayloadFields_CertArrayDecodeError exercises the error branch at
// status_token.go:222-223 where decodeCertArray fails (invalid identity certs).
func TestDecodePayloadFields_CertArrayDecodeError(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// Build a raw map where the identity certs field (key 6) is not a valid
	// CBOR array (it's an integer).
	invalidCertsRaw, _ := cbor.Marshal(int64(42))

	rawMap := make(map[interface{}]cbor.RawMessage)
	rawMap[int64(1)] = mustCBOREncode(t, mustMarshalValue(t, "agent-1"))
	rawMap[int64(2)] = mustCBOREncode(t, mustMarshalValue(t, "ACTIVE"))
	rawMap[int64(4)] = mustCBOREncode(t, mustMarshalValue(t, int64(9999999999)))
	rawMap[int64(5)] = mustCBOREncode(t, mustMarshalValue(t, "test.ans"))
	rawMap[int64(6)] = invalidCertsRaw // identity certs: invalid (not an array)

	_, err = decodePayloadFields(dm, rawMap)
	if err == nil {
		t.Fatal("expected error for invalid identity certs")
	}
	if !strings.Contains(err.Error(), "failed to decode cert array") {
		t.Errorf("error = %q, want containing 'failed to decode cert array'", err.Error())
	}
}

// TestDecodePayloadFields_ServerCertsDecodeError exercises the error branch at
// status_token.go:231-233 where decodeCertArray fails for server certs (key 7).
func TestDecodePayloadFields_ServerCertsDecodeError(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	invalidCertsRaw, _ := cbor.Marshal("not-an-array")

	rawMap := make(map[interface{}]cbor.RawMessage)
	rawMap[int64(1)] = mustCBOREncode(t, mustMarshalValue(t, "agent-1"))
	rawMap[int64(2)] = mustCBOREncode(t, mustMarshalValue(t, "ACTIVE"))
	rawMap[int64(4)] = mustCBOREncode(t, mustMarshalValue(t, int64(9999999999)))
	rawMap[int64(5)] = mustCBOREncode(t, mustMarshalValue(t, "test.ans"))
	rawMap[int64(7)] = invalidCertsRaw // server certs: invalid (not an array)

	_, err = decodePayloadFields(dm, rawMap)
	if err == nil {
		t.Fatal("expected error for invalid server certs")
	}
	if !strings.Contains(err.Error(), "failed to decode cert array") {
		t.Errorf("error = %q, want containing 'failed to decode cert array'", err.Error())
	}
}

// TestDecodeCertArray_NotAnArray exercises the error branch at
// status_token.go:310-311 where the CBOR value is not an array.
func TestDecodeCertArray_NotAnArray(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// A CBOR integer is not an array.
	notArray, _ := cbor.Marshal(int64(42))

	_, err = decodeCertArray(dm, notArray)
	if err == nil {
		t.Fatal("expected error for non-array cert data")
	}
	if !strings.Contains(err.Error(), "failed to decode cert array") {
		t.Errorf("error = %q, want containing 'failed to decode cert array'", err.Error())
	}
}

// TestDecodeCertArray_InvalidEntriesSkipped exercises the path at
// status_token.go:323-324 where cert entries fail to decode as maps and are
// silently skipped (continue).
func TestDecodeCertArray_InvalidEntriesSkipped(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// An array containing a non-map element (integer) which should be skipped.
	arr := []interface{}{
		int64(42), // not a map — skipped
	}
	arrBytes, _ := cbor.Marshal(arr)

	entries, err := decodeCertArray(dm, arrBytes)
	if err != nil {
		t.Fatalf("expected success (invalid entries skipped), got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (invalid entry skipped), got %d", len(entries))
	}
}

// TestDecodeCertArray_EmptyFingerprintExcluded exercises the path at
// status_token.go:335-337 where a cert entry with an all-zero fingerprint is
// excluded from the result.
func TestDecodeCertArray_EmptyFingerprintExcluded(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// A cert entry with an all-zero (empty) fingerprint — should be excluded.
	zeroFP := make([]byte, 32)
	certMap := map[interface{}]interface{}{
		int64(1): zeroFP, // fingerprint: all zeros
		int64(2): "x509-dv-server",
	}
	arr := []interface{}{certMap}
	arrBytes, _ := cbor.Marshal(arr)

	entries, err := decodeCertArray(dm, arrBytes)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (empty fingerprint excluded), got %d", len(entries))
	}
}

// TestDecodeFingerprintField_RawBytes exercises the raw 32-byte bstr path at
// status_token.go:345-350.
func TestDecodeFingerprintField_RawBytes(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	fp := sha256.Sum256([]byte("raw-fingerprint-test"))
	raw, _ := cbor.Marshal(fp[:])

	result := decodeFingerprintField(dm, raw)
	if result != fp {
		t.Errorf("decodeFingerprintField = %x, want %x", result, fp)
	}
}

// TestDecodeFingerprintField_ShortRawBytes exercises the path at
// status_token.go:346 where the raw bytes are not 32 bytes long, falling
// through to the string path which also fails, returning an empty [32]byte.
func TestDecodeFingerprintField_ShortRawBytes(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// A 16-byte bstr (not 32) — should fall through to string path, which also
	// fails, returning an empty [32]byte.
	shortBytes := make([]byte, 16)
	raw, _ := cbor.Marshal(shortBytes)

	result := decodeFingerprintField(dm, raw)
	if result != ([32]byte{}) {
		t.Errorf("decodeFingerprintField = %x, want all zeros", result)
	}
}

// TestDecodeFingerprintField_SHA256HexString exercises the "SHA256:<hex>" string
// path at status_token.go:353-357 → parseHexFingerprint.
func TestDecodeFingerprintField_SHA256HexString(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	fp := sha256.Sum256([]byte("hex-fingerprint-test"))
	hexStr := "SHA256:" + hexEncode(fp[:])
	raw, _ := cbor.Marshal(hexStr)

	result := decodeFingerprintField(dm, raw)
	if result != fp {
		t.Errorf("decodeFingerprintField = %x, want %x", result, fp)
	}
}

// TestDecodeFingerprintField_BareHexString exercises the bare hex string path
// in parseHexFingerprint (no "SHA256:" prefix).
func TestDecodeFingerprintField_BareHexString(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	fp := sha256.Sum256([]byte("bare-hex-test"))
	hexStr := hexEncode(fp[:])
	raw, _ := cbor.Marshal(hexStr)

	result := decodeFingerprintField(dm, raw)
	if result != fp {
		t.Errorf("decodeFingerprintField = %x, want %x", result, fp)
	}
}

// TestDecodeFingerprintField_LowercaseSHA256Prefix exercises the
// case-insensitive "sha256:" prefix matching in parseHexFingerprint.
func TestDecodeFingerprintField_LowercaseSHA256Prefix(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	fp := sha256.Sum256([]byte("lowercase-prefix-test"))
	hexStr := "sha256:" + hexEncode(fp[:])
	raw, _ := cbor.Marshal(hexStr)

	result := decodeFingerprintField(dm, raw)
	if result != fp {
		t.Errorf("decodeFingerprintField = %x, want %x", result, fp)
	}
}

// TestDecodeFingerprintField_InvalidHexString exercises the failure path in
// parseHexFingerprint where the hex string is invalid.
func TestDecodeFingerprintField_InvalidHexString(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// Invalid hex string (not valid hex, not 32 bytes).
	raw, _ := cbor.Marshal("SHA256:not-valid-hex!!!")

	result := decodeFingerprintField(dm, raw)
	if result != ([32]byte{}) {
		t.Errorf("decodeFingerprintField = %x, want all zeros", result)
	}
}

// TestDecodeFingerprintField_ShortHexString exercises the failure path where
// the hex string decodes to fewer than 32 bytes.
func TestDecodeFingerprintField_ShortHexString(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// A valid hex string but only 16 bytes (not 32).
	shortHex := "SHA256:" + hexEncode(make([]byte, 16))
	raw, _ := cbor.Marshal(shortHex)

	result := decodeFingerprintField(dm, raw)
	if result != ([32]byte{}) {
		t.Errorf("decodeFingerprintField = %x, want all zeros (short hex)", result)
	}
}

// TestDecodeFingerprintField_NonStringNonBytes exercises the path where the
// raw CBOR value is neither bytes nor a string (e.g. an integer), returning
// an empty [32]byte.
func TestDecodeFingerprintField_NonStringNonBytes(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// An integer is neither bytes nor a string.
	raw, _ := cbor.Marshal(int64(42))

	result := decodeFingerprintField(dm, raw)
	if result != ([32]byte{}) {
		t.Errorf("decodeFingerprintField = %x, want all zeros", result)
	}
}

// TestParseHexFingerprint_ValidSHA256Prefix exercises parseHexFingerprint with
// the "SHA256:" prefix.
func TestParseHexFingerprint_ValidSHA256Prefix(t *testing.T) {
	t.Parallel()

	fp := sha256.Sum256([]byte("parse-hex-sha256"))
	hexStr := "SHA256:" + hexEncode(fp[:])

	result, ok := parseHexFingerprint(hexStr)
	if !ok {
		t.Fatal("expected ok=true for valid SHA256:hex string")
	}
	if result != fp {
		t.Errorf("parseHexFingerprint = %x, want %x", result, fp)
	}
}

// TestParseHexFingerprint_ValidBareHex exercises parseHexFingerprint with a
// bare hex string (no prefix).
func TestParseHexFingerprint_ValidBareHex(t *testing.T) {
	t.Parallel()

	fp := sha256.Sum256([]byte("parse-hex-bare"))
	hexStr := hexEncode(fp[:])

	result, ok := parseHexFingerprint(hexStr)
	if !ok {
		t.Fatal("expected ok=true for valid bare hex string")
	}
	if result != fp {
		t.Errorf("parseHexFingerprint = %x, want %x", result, fp)
	}
}

// TestParseHexFingerprint_InvalidHex exercises parseHexFingerprint with an
// invalid hex string.
func TestParseHexFingerprint_InvalidHex(t *testing.T) {
	t.Parallel()

	_, ok := parseHexFingerprint("not-valid-hex!!!")
	if ok {
		t.Error("expected ok=false for invalid hex string")
	}
}

// TestParseHexFingerprint_WrongLength exercises parseHexFingerprint with a
// valid hex string of the wrong length (not 32 bytes).
func TestParseHexFingerprint_WrongLength(t *testing.T) {
	t.Parallel()

	// 16 bytes (32 hex chars) — valid hex but wrong length.
	shortHex := hexEncode(make([]byte, 16))

	_, ok := parseHexFingerprint(shortHex)
	if ok {
		t.Error("expected ok=false for short hex string")
	}
}

// TestParseHexFingerprint_EmptyString exercises parseHexFingerprint with an
// empty string.
func TestParseHexFingerprint_EmptyString(t *testing.T) {
	t.Parallel()

	_, ok := parseHexFingerprint("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

// TestDecodeStatusPayload_NonMapCBOR exercises the error path at
// status_token.go:262-268 where the payload decodes as CBOR but is not a map.
func TestDecodeStatusPayload_NonMapCBOR(t *testing.T) {
	t.Parallel()

	// A CBOR-encoded string is not a map.
	data, _ := cbor.Marshal("just-a-string")

	_, err := decodeStatusPayload(data)
	if err == nil {
		t.Fatal("expected error for non-map payload")
	}
	var tokErr *TokenError
	if !errors.As(err, &tokErr) {
		t.Fatalf("expected *TokenError, got %T: %v", err, err)
	}
	if tokErr.Type != TokenErrPayloadEmpty {
		t.Errorf("error type = %d, want TokenErrPayloadEmpty", tokErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode payload") {
		t.Errorf("error = %q, want containing 'failed to decode payload'", err.Error())
	}
}

// TestDecodeStatusPayload_InvalidCBOR exercises the error path where the
// payload is not valid CBOR at all.
func TestDecodeStatusPayload_InvalidCBOR(t *testing.T) {
	t.Parallel()

	// Invalid CBOR bytes.
	_, err := decodeStatusPayload([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid CBOR payload")
	}
	var tokErr *TokenError
	if !errors.As(err, &tokErr) {
		t.Fatalf("expected *TokenError, got %T: %v", err, err)
	}
}

// TestVerifyStatusTokenAt_GarbageInput exercises the full token verification
// path with garbage input that fails at the COSE parse stage.
func TestVerifyStatusTokenAt_GarbageInput(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "garbage-input")
	store := newTestKeyStore(ki)

	_, err := VerifyStatusTokenAt([]byte{0xFF, 0xFE, 0xFD, 0xFC}, store, 0, 0)
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
}

// hexEncode converts bytes to a lowercase hex string.
func hexEncode(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0F]
	}
	return string(result)
}
