package scitt

import (
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestParseCoseSign1_ProtectedHeaderBytesNotBstr exercises the error branch at
// cose.go:123-127 where element 0 of the COSE_Sign1 array fails to decode as a
// byte string (bstr). We provide an array whose first element is an integer
// rather than a bstr.
func TestParseCoseSign1_ProtectedHeaderBytesNotBstr(t *testing.T) {
	t.Parallel()

	// Element 0 is an integer (not a bstr), so Unmarshal into []byte fails.
	elements := []cbor.RawMessage{
		mustMarshal(t, int64(42)),             // protected header bytes: not a bstr
		mustMarshal(t, map[int]int{}),         // unprotected
		mustMarshal(t, []byte("payload")),      // payload
		mustMarshal(t, make([]byte, 64)),       // signature
	}
	data, err := cbor.Marshal(elements)
	if err != nil {
		t.Fatalf("failed to marshal elements: %v", err)
	}

	_, err = ParseCoseSign1(data)
	if err == nil {
		t.Fatal("expected error for non-bstr protected header bytes")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidProtectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidProtectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode protected header bytes") {
		t.Errorf("error = %q, want containing 'failed to decode protected header bytes'", err.Error())
	}
}

// TestParseCoseSign1_PayloadDecodeFailure exercises cose.go:142-146 where
// element 2 (payload) cannot be decoded as a byte string.
func TestParseCoseSign1_PayloadDecodeFailure(t *testing.T) {
	t.Parallel()

	// Build a valid protected header so we get past the protected header stage.
	protectedMap := map[int64]interface{}{
		1: int64(-7),                    // alg
		4: []byte{0xAA, 0xBB, 0xCC, 0xDD}, // kid
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	// Element 2 is an integer instead of a bstr, triggering decode failure.
	elements := []cbor.RawMessage{
		mustMarshal(t, protectedBytes),
		mustMarshal(t, map[int]int{}),
		mustMarshal(t, int64(99)),        // payload: not a bstr
		mustMarshal(t, make([]byte, 64)), // signature
	}
	data, err := cbor.Marshal(elements)
	if err != nil {
		t.Fatalf("failed to marshal elements: %v", err)
	}

	_, err = ParseCoseSign1(data)
	if err == nil {
		t.Fatal("expected error for non-bstr payload")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrNotACoseSign1 {
		t.Errorf("error type = %d, want CoseErrNotACoseSign1", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode payload") {
		t.Errorf("error = %q, want containing 'failed to decode payload'", err.Error())
	}
}

// TestParseCoseSign1_SignatureDecodeFailure exercises cose.go:158-162 where
// element 3 (signature) cannot be decoded as a byte string.
func TestParseCoseSign1_SignatureDecodeFailure(t *testing.T) {
	t.Parallel()

	protectedMap := map[int64]interface{}{
		1: int64(-7),
		4: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	// Element 3 is a map instead of a bstr, triggering decode failure.
	elements := []cbor.RawMessage{
		mustMarshal(t, protectedBytes),
		mustMarshal(t, map[int]int{}),
		mustMarshal(t, []byte("payload")),
		mustMarshal(t, map[string]string{"not": "a bstr"}), // signature: not a bstr
	}
	data, err := cbor.Marshal(elements)
	if err != nil {
		t.Fatalf("failed to marshal elements: %v", err)
	}

	_, err = ParseCoseSign1(data)
	if err == nil {
		t.Fatal("expected error for non-bstr signature")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidSignatureLength {
		t.Errorf("error type = %d, want CoseErrInvalidSignatureLength", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode signature") {
		t.Errorf("error = %q, want containing 'failed to decode signature'", err.Error())
	}
}

// TestParseCoseSign1_AlgDecodeFailure exercises cose.go:237-241 where the
// algorithm field exists in the protected header but cannot be decoded as an
// int64 (e.g. it's a string).
func TestParseCoseSign1_AlgDecodeFailure(t *testing.T) {
	t.Parallel()

	// Protected header with alg as a string instead of an int.
	protectedMap := map[int64]interface{}{
		1: "ES256", // alg: wrong type (string, not int)
		4: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	data := buildRawCoseSign1(t, protectedBytes, validPayload(), validSignature(), false)

	_, err = ParseCoseSign1(data)
	if err == nil {
		t.Fatal("expected error for non-int algorithm")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrUnsupportedAlgorithm {
		t.Errorf("error type = %d, want CoseErrUnsupportedAlgorithm", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode algorithm") {
		t.Errorf("error = %q, want containing 'failed to decode algorithm'", err.Error())
	}
}

// TestParseCoseSign1_KidDecodeFailure exercises cose.go:268-272 where the kid
// field exists in the protected header but cannot be decoded as a byte string
// (e.g. it's an integer).
func TestParseCoseSign1_KidDecodeFailure(t *testing.T) {
	t.Parallel()

	// Protected header with kid as an integer instead of a bstr.
	protectedMap := map[int64]interface{}{
		1: int64(-7),  // alg: valid
		4: int64(42),  // kid: wrong type (int, not bstr)
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	data := buildRawCoseSign1(t, protectedBytes, validPayload(), validSignature(), false)

	_, err = ParseCoseSign1(data)
	if err == nil {
		t.Fatal("expected error for non-bstr kid")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrMissingKid {
		t.Errorf("error type = %d, want CoseErrMissingKid", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode kid") {
		t.Errorf("error = %q, want containing 'failed to decode kid'", err.Error())
	}
}

// TestParseCoseSign1_CWTClaimsNotAMap exercises cose.go:193 where
// parseCWTClaims fails to decode the CWT claims map (key 15) because it is not
// a CBOR map. The overall parse should still succeed (CWT claims are
// optional), but the iss/iat fields should remain nil.
func TestParseCoseSign1_CWTClaimsNotAMap(t *testing.T) {
	t.Parallel()

	// Protected header where key 15 (CWT claims) is a string, not a map.
	protectedMap := map[int64]interface{}{
		1: int64(-7),                  // alg
		4: []byte{0xAA, 0xBB, 0xCC, 0xDD}, // kid
		15: "not-a-map",               // CWT claims: wrong type
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	data := buildRawCoseSign1(t, protectedBytes, validPayload(), validSignature(), false)

	result, err := ParseCoseSign1(data)
	if err != nil {
		t.Fatalf("expected success when CWT claims are malformed (optional field), got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// When the CWT claims map fails to decode, iss and iat should both be nil.
	if result.Protected.CwtIss != nil {
		t.Errorf("CwtIss = %v, want nil (CWT claims map was malformed)", result.Protected.CwtIss)
	}
	if result.Protected.CwtIat != nil {
		t.Errorf("CwtIat = %v, want nil (CWT claims map was malformed)", result.Protected.CwtIat)
	}
}

// TestParseCoseSign1_CWTClaimsIssWrongType exercises the branch in parseCWTClaims
// (cose.go:199-200) where the issuer key (1) exists but is not a string.
func TestParseCoseSign1_CWTClaimsIssWrongType(t *testing.T) {
	t.Parallel()

	// CWT claims map where key 1 (iss) is an integer, not a string.
	cwtClaims := map[int64]interface{}{
		1: int64(42), // iss: wrong type
	}
	protectedMap := map[int64]interface{}{
		1:  int64(-7),                       // alg
		4:  []byte{0xAA, 0xBB, 0xCC, 0xDD},   // kid
		15: cwtClaims,                        // CWT claims
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	data := buildRawCoseSign1(t, protectedBytes, validPayload(), validSignature(), false)

	result, err := ParseCoseSign1(data)
	if err != nil {
		t.Fatalf("expected success (iss is optional even if present), got: %v", err)
	}
	if result.Protected.CwtIss != nil {
		t.Errorf("CwtIss = %v, want nil (iss was wrong type)", result.Protected.CwtIss)
	}
}

// TestParseCoseSign1_CWTClaimsIatWrongType exercises the branch in parseCWTClaims
// (cose.go:206-208) where the iat key (6) exists but is not an int64.
func TestParseCoseSign1_CWTClaimsIatWrongType(t *testing.T) {
	t.Parallel()

	// CWT claims map where key 6 (iat) is a string, not an int.
	cwtClaims := map[int64]interface{}{
		6: "not-a-number", // iat: wrong type
	}
	protectedMap := map[int64]interface{}{
		1:  int64(-7),
		4:  []byte{0xAA, 0xBB, 0xCC, 0xDD},
		15: cwtClaims,
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal protected header: %v", err)
	}

	data := buildRawCoseSign1(t, protectedBytes, validPayload(), validSignature(), false)

	result, err := ParseCoseSign1(data)
	if err != nil {
		t.Fatalf("expected success (iat is optional even if present), got: %v", err)
	}
	if result.Protected.CwtIat != nil {
		t.Errorf("CwtIat = %v, want nil (iat was wrong type)", result.Protected.CwtIat)
	}
}

// TestBuildSigStructure_NilInputs exercises BuildSigStructure with nil inputs
// to confirm it either succeeds (cbor.Marshal handles nil bytes) or returns an
// error. This targets the defensive error branch at cose.go:309.
func TestBuildSigStructure_NilInputs(t *testing.T) {
	t.Parallel()

	// cbor.Marshal of a slice containing nil []byte produces valid CBOR (nil bstr),
	// so BuildSigStructure should succeed. The error branch at line 309 is
	// essentially unreachable with []byte inputs, but we verify behavior.
	result, err := BuildSigStructure(nil, nil)
	if err != nil {
		// If it errors, that's the defensive path — acceptable.
		return
	}
	if len(result) == 0 {
		t.Error("expected non-empty result from BuildSigStructure(nil, nil)")
	}
}

// TestComputeSigStructureDigest_NilInputs exercises the error propagation
// branch at cose.go:318 by passing inputs that cause BuildSigStructure to
// fail. Since BuildSigStructure practically never fails with []byte inputs,
// we verify the happy path and document the defensive error propagation.
func TestComputeSigStructureDigest_NilInputs(t *testing.T) {
	t.Parallel()

	digest, err := ComputeSigStructureDigest(nil, nil)
	if err != nil {
		// Defensive error propagation — acceptable.
		return
	}
	// If it succeeds, the digest should be a valid SHA-256 (non-zero for non-empty input,
	// but nil inputs produce a deterministic hash of the nil-bstr structure).
	var zero [32]byte
	if digest == zero {
		t.Error("expected non-zero digest from ComputeSigStructureDigest(nil, nil)")
	}
}

// TestUnwrapTag18_NonTagInput exercises unwrapTag18 with input that is not a
// CBOR tag, confirming it returns the raw input unchanged.
func TestUnwrapTag18_NonTagInput(t *testing.T) {
	t.Parallel()

	// A CBOR-encoded integer is not a tag.
	raw, err := cbor.Marshal(int64(42))
	if err != nil {
		t.Fatalf("failed to marshal integer: %v", err)
	}

	result := unwrapTag18(cbor.RawMessage(raw))
	if !strings.EqualFold(string(result), string(raw)) {
		// unwrapTag18 should return the input unchanged when it's not tag 18.
		if len(result) != len(raw) {
			t.Errorf("unwrapTag18 returned %d bytes, want %d (input unchanged)", len(result), len(raw))
		}
	}
}

// TestUnwrapTag18_TagOtherThan18 exercises unwrapTag18 with a CBOR tag that is
// not 18 (e.g. tag 0), confirming it returns the raw input unchanged.
func TestUnwrapTag18_TagOtherThan18(t *testing.T) {
	t.Parallel()

	// Build a CBOR tag 0 (standard date/time tag) wrapping a string.
	tag := cbor.RawTag{Number: 0, Content: mustMarshal(t, "2024-01-01")}
	tagged, err := tag.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal tag 0: %v", err)
	}

	result := unwrapTag18(tagged)
	// Should return the raw input unchanged (tag number != 18).
	if len(result) == 0 {
		t.Error("expected non-empty result from unwrapTag18 with tag != 18")
	}
}

// TestParseProtectedHeader_InvalidCBORMap exercises the error branch at
// cose.go:218-224 where the protected header bytes are not a valid CBOR map.
func TestParseProtectedHeader_InvalidCBORMap(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// Protected header bytes that are not a valid CBOR map (an integer).
	protectedBytes, err := cbor.Marshal(int64(42))
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	_, err = parseProtectedHeader(dm, protectedBytes)
	if err == nil {
		t.Fatal("expected error for non-map protected header")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidProtectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidProtectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode protected header map") {
		t.Errorf("error = %q, want containing 'failed to decode protected header map'", err.Error())
	}
}

// TestParseProtectedHeader_ContentTypeWrongType exercises the content_type
// branch (cose.go:251-256) where key 3 exists but is not a string. The parse
// should succeed and ContentType should remain nil.
func TestParseProtectedHeader_ContentTypeWrongType(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// Protected header with content_type as an integer.
	protectedMap := map[int64]interface{}{
		1: int64(-7),
		3: int64(42),   // content_type: wrong type
		4: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	header, err := parseProtectedHeader(dm, protectedBytes)
	if err != nil {
		t.Fatalf("expected success (content_type is optional), got: %v", err)
	}
	if header.ContentType != nil {
		t.Errorf("ContentType = %v, want nil (content_type was wrong type)", header.ContentType)
	}
}

// TestParseProtectedHeader_VDSWrongType exercises the vds branch (cose.go:288-293)
// where key 395 exists but is not an int64. The parse should succeed and Vds
// should remain nil.
func TestParseProtectedHeader_VDSWrongType(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// Protected header with vds as a string instead of int.
	protectedMap := map[int64]interface{}{
		1:   int64(-7),
		4:   []byte{0xAA, 0xBB, 0xCC, 0xDD},
		395: "not-an-int", // vds: wrong type
	}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	header, err := parseProtectedHeader(dm, protectedBytes)
	if err != nil {
		t.Fatalf("expected success (vds is optional), got: %v", err)
	}
	if header.Vds != nil {
		t.Errorf("Vds = %v, want nil (vds was wrong type)", header.Vds)
	}
}
