package scitt

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestExtractVDP_TreeSizeNotInteger exercises the error branch at
// receipt.go:184-188 where tree_size (key -1) exists but is not an unsigned
// integer (e.g. it's a string).
func TestExtractVDP_TreeSizeNotInteger(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with tree_size as a string instead of uint.
	vdp := map[int64]interface{}{
		int64(-1): "not-a-uint",
		int64(-2): uint64(0),
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	_, _, _, err = extractVDP(dm, raw)
	if err == nil {
		t.Fatal("expected error for non-integer tree_size")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidUnprotectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "tree_size (key -1) must be an unsigned integer") {
		t.Errorf("error = %q, want containing 'tree_size (key -1) must be an unsigned integer'", err.Error())
	}
}

// TestExtractVDP_LeafIndexNotInteger exercises the error branch at
// receipt.go:200-204 where leaf_index (key -2) exists but is not an unsigned
// integer (e.g. it's a string).
func TestExtractVDP_LeafIndexNotInteger(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with leaf_index as a string instead of uint.
	vdp := map[int64]interface{}{
		int64(-1): uint64(4),
		int64(-2): "not-a-uint",
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	_, _, _, err = extractVDP(dm, raw)
	if err == nil {
		t.Fatal("expected error for non-integer leaf_index")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidUnprotectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "leaf_index (key -2) must be an unsigned integer") {
		t.Errorf("error = %q, want containing 'leaf_index (key -2) must be an unsigned integer'", err.Error())
	}
}

// TestExtractVDP_InclusionPathNotArray exercises the error branch at
// receipt.go:214-218 where inclusion_path (key -3) exists but is not a CBOR
// array (e.g. it's an integer).
func TestExtractVDP_InclusionPathNotArray(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with inclusion_path as an integer instead of an array.
	vdp := map[int64]interface{}{
		int64(-1): uint64(4),
		int64(-2): uint64(0),
		int64(-3): int64(42), // not an array
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	_, _, _, err = extractVDP(dm, raw)
	if err == nil {
		t.Fatal("expected error for non-array inclusion_path")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidUnprotectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "inclusion_path (key -3) must be a CBOR array") {
		t.Errorf("error = %q, want containing 'inclusion_path (key -3) must be a CBOR array'", err.Error())
	}
}

// TestExtractVDP_InclusionPathElementNotBstr exercises the error branch at
// receipt.go:225-229 where an element of the inclusion_path array cannot be
// decoded as a byte string.
func TestExtractVDP_InclusionPathElementNotBstr(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with inclusion_path containing a non-bstr element (integer).
	vdp := map[int64]interface{}{
		int64(-1): uint64(4),
		int64(-2): uint64(0),
		int64(-3): []interface{}{int64(42)}, // element is not a bstr
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	_, _, _, err = extractVDP(dm, raw)
	if err == nil {
		t.Fatal("expected error for non-bstr inclusion_path element")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidUnprotectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "failed to decode inclusion_path element 0") {
		t.Errorf("error = %q, want containing 'failed to decode inclusion_path element 0'", err.Error())
	}
}

// TestExtractVDP_InclusionPathElementWrongLength exercises the error branch at
// receipt.go:232-235 where an inclusion_path element decodes as a byte string
// but is not exactly 32 bytes long.
func TestExtractVDP_InclusionPathElementWrongLength(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with inclusion_path containing a 16-byte bstr (not 32).
	vdp := map[int64]interface{}{
		int64(-1): uint64(4),
		int64(-2): uint64(0),
		int64(-3): []interface{}{make([]byte, 16)}, // 16 bytes, not 32
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	_, _, _, err = extractVDP(dm, raw)
	if err == nil {
		t.Fatal("expected error for wrong-length inclusion_path element")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidUnprotectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "inclusion_path element 0 is 16 bytes, expected 32") {
		t.Errorf("error = %q, want containing 'inclusion_path element 0 is 16 bytes, expected 32'", err.Error())
	}
}

// TestExtractVDP_EmptyInclusionPath exercises the path at receipt.go:207-210
// where the inclusion_path key (-3) is missing from the VDP map. This should
// return (treeSize, leafIndex, nil, nil) without error.
func TestExtractVDP_EmptyInclusionPath(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map without the inclusion_path key (-3).
	vdp := map[int64]interface{}{
		int64(-1): uint64(1),
		int64(-2): uint64(0),
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	treeSize, leafIndex, hashPath, err := extractVDP(dm, raw)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if treeSize != 1 {
		t.Errorf("treeSize = %d, want 1", treeSize)
	}
	if leafIndex != 0 {
		t.Errorf("leafIndex = %d, want 0", leafIndex)
	}
	if hashPath != nil {
		t.Errorf("hashPath = %v, want nil", hashPath)
	}
}

// TestExtractVDP_EmptyInclusionPathArray exercises the path where the
// inclusion_path key (-3) exists but the array is empty. This should return
// an empty (non-nil) hashPath.
func TestExtractVDP_EmptyInclusionPathArray(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with an empty inclusion_path array.
	vdp := map[int64]interface{}{
		int64(-1): uint64(1),
		int64(-2): uint64(0),
		int64(-3): []interface{}{}, // empty array
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	treeSize, leafIndex, hashPath, err := extractVDP(dm, raw)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if treeSize != 1 {
		t.Errorf("treeSize = %d, want 1", treeSize)
	}
	if leafIndex != 0 {
		t.Errorf("leafIndex = %d, want 0", leafIndex)
	}
	if hashPath == nil {
		t.Error("expected non-nil hashPath (empty slice)")
	}
	if len(hashPath) != 0 {
		t.Errorf("len(hashPath) = %d, want 0", len(hashPath))
	}
}

// TestExtractVDP_ValidHashPath exercises the happy path of extractVDP where
// the inclusion_path contains valid 32-byte bstr elements.
func TestExtractVDP_ValidHashPath(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	fp1 := sha256.Sum256([]byte("valid-path-1"))
	fp2 := sha256.Sum256([]byte("valid-path-2"))

	vdp := map[int64]interface{}{
		int64(-1): uint64(4),
		int64(-2): uint64(0),
		int64(-3): []interface{}{fp1[:], fp2[:]},
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	treeSize, leafIndex, hashPath, err := extractVDP(dm, raw)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if treeSize != 4 {
		t.Errorf("treeSize = %d, want 4", treeSize)
	}
	if leafIndex != 0 {
		t.Errorf("leafIndex = %d, want 0", leafIndex)
	}
	if len(hashPath) != 2 {
		t.Fatalf("len(hashPath) = %d, want 2", len(hashPath))
	}
	if hashPath[0] != fp1 {
		t.Errorf("hashPath[0] = %x, want %x", hashPath[0], fp1)
	}
	if hashPath[1] != fp2 {
		t.Errorf("hashPath[1] = %x, want %x", hashPath[1], fp2)
	}
}

// TestExtractVDP_NegativeTreeSize exercises the path where tree_size is a
// negative int64. Since the VDP map uses int64 keys and uint64 values, a
// negative value should fail to decode as uint64.
func TestExtractVDP_NegativeTreeSize(t *testing.T) {
	t.Parallel()

	dm, err := newDecMode()
	if err != nil {
		t.Fatalf("failed to create decode mode: %v", err)
	}

	// VDP map with tree_size as a negative int64.
	vdp := map[int64]interface{}{
		int64(-1): int64(-1), // negative tree_size
		int64(-2): uint64(0),
	}
	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}
	raw, _ := cbor.Marshal(unprotected)

	_, _, _, err = extractVDP(dm, raw)
	if err == nil {
		t.Fatal("expected error for negative tree_size")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidUnprotectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
	}
}

// TestValidateVDS_Nil exercises validateVDS with a nil vds pointer,
// targeting the error branch at receipt.go:91-96.
func TestValidateVDS_Nil(t *testing.T) {
	t.Parallel()

	err := validateVDS(nil)
	if err == nil {
		t.Fatal("expected error for nil vds")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidProtectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidProtectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "missing vds") {
		t.Errorf("error = %q, want containing 'missing vds'", err.Error())
	}
}

// TestValidateVDS_WrongValue exercises validateVDS with a vds value that is
// not 1 (RFC 9162), targeting the error branch at receipt.go:97-102.
func TestValidateVDS_WrongValue(t *testing.T) {
	t.Parallel()

	vds := int64(99)
	err := validateVDS(&vds)
	if err == nil {
		t.Fatal("expected error for wrong vds value")
	}
	var coseErr *CoseError
	if !errors.As(err, &coseErr) {
		t.Fatalf("expected *CoseError, got %T: %v", err, err)
	}
	if coseErr.Type != CoseErrInvalidProtectedHeader {
		t.Errorf("error type = %d, want CoseErrInvalidProtectedHeader", coseErr.Type)
	}
	if !strings.Contains(err.Error(), "expected vds=1") {
		t.Errorf("error = %q, want containing 'expected vds=1'", err.Error())
	}
}

// TestValidateVDS_CorrectValue exercises validateVDS with the correct vds
// value (1 = RFC 9162), confirming it returns nil.
func TestValidateVDS_CorrectValue(t *testing.T) {
	t.Parallel()

	vds := int64(1)
	err := validateVDS(&vds)
	if err != nil {
		t.Errorf("expected nil for correct vds, got: %v", err)
	}
}

// TestVerifyIssuerBinding_NilIss exercises verifyIssuerBinding with a nil iss
// pointer, confirming it returns nil (no issuer binding check needed).
func TestVerifyIssuerBinding_NilIss(t *testing.T) {
	t.Parallel()

	key := &TrustedKey{Name: "test-key", Kid: [4]byte{0x01, 0x02, 0x03, 0x04}}
	err := verifyIssuerBinding(nil, key)
	if err != nil {
		t.Errorf("expected nil for nil iss, got: %v", err)
	}
}

// TestVerifyIssuerBinding_MatchingIss exercises verifyIssuerBinding where the
// iss matches the key name, confirming it returns nil.
func TestVerifyIssuerBinding_MatchingIss(t *testing.T) {
	t.Parallel()

	key := &TrustedKey{Name: "matching-issuer", Kid: [4]byte{0x01, 0x02, 0x03, 0x04}}
	iss := "matching-issuer"
	err := verifyIssuerBinding(&iss, key)
	if err != nil {
		t.Errorf("expected nil for matching iss, got: %v", err)
	}
}

// TestVerifyIssuerBinding_MismatchingIss exercises verifyIssuerBinding where
// the iss does not match the key name, targeting the error branch at
// receipt.go:112-118.
func TestVerifyIssuerBinding_MismatchingIss(t *testing.T) {
	t.Parallel()

	key := &TrustedKey{Name: "correct-issuer", Kid: [4]byte{0x01, 0x02, 0x03, 0x04}}
	iss := "wrong-issuer"
	err := verifyIssuerBinding(&iss, key)
	if err == nil {
		t.Fatal("expected error for mismatching iss")
	}
	var sigErr *SignatureError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected *SignatureError, got %T: %v", err, err)
	}
	if sigErr.Type != SigErrIssuerMismatch {
		t.Errorf("error type = %d, want SigErrIssuerMismatch", sigErr.Type)
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("error = %q, want containing 'issuer'", err.Error())
	}
}
