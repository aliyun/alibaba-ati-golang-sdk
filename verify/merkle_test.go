package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

func hexHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func testMerkleNodeHash(left, right string) string {
	lb, _ := hex.DecodeString(left)
	rb, _ := hex.DecodeString(right)
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(lb)
	h.Write(rb)
	return hex.EncodeToString(h.Sum(nil))
}

func buildMerkleTestResponse(leafHash string, rootHash string, leafIndex int64, treeSize int64, path []string) *models.TLResponse {
	return &models.TLResponse{
		Status:        "ACTIVE",
		SchemaVersion: "1.0",
		Payload: models.TLPayload{
			AgentID:     "ans-merkle-001",
			AgentName:   "ati://merkle.example.com",
			AgentStatus: "ACTIVE",
		},
		MerkleProof: models.MerkleProof{
			LeafHash:  leafHash,
			RootHash:  rootHash,
			LeafIndex: leafIndex,
			TreeSize:  treeSize,
			Path:      path,
		},
	}
}

func TestVerifyInclusionProof_SingleLeaf(t *testing.T) {
	leafH := hexHash([]byte("leaf-data"))

	resp := buildMerkleTestResponse(leafH, leafH, 0, 1, []string{})

	if err := VerifyInclusionProof(resp); err != nil {
		t.Fatalf("VerifyInclusionProof() error = %v", err)
	}
}

func TestVerifyInclusionProof_TwoLeaves_Left(t *testing.T) {
	leafH := hexHash([]byte("my-leaf-data"))
	otherLeaf := hexHash([]byte("other-leaf-data"))
	root := testMerkleNodeHash(leafH, otherLeaf)

	resp := buildMerkleTestResponse(leafH, root, 0, 2, []string{otherLeaf})

	if err := VerifyInclusionProof(resp); err != nil {
		t.Fatalf("VerifyInclusionProof() error = %v", err)
	}
}

func TestVerifyInclusionProof_TwoLeaves_Right(t *testing.T) {
	leafH := hexHash([]byte("my-leaf-data"))
	otherLeaf := hexHash([]byte("first-leaf-data"))
	root := testMerkleNodeHash(otherLeaf, leafH)

	resp := buildMerkleTestResponse(leafH, root, 1, 2, []string{otherLeaf})

	if err := VerifyInclusionProof(resp); err != nil {
		t.Fatalf("VerifyInclusionProof() error = %v", err)
	}
}

func TestVerifyInclusionProof_RootMismatch(t *testing.T) {
	leafH := hexHash([]byte("leaf-data"))
	wrongRoot := hexHash([]byte("wrong-root"))

	resp := buildMerkleTestResponse(leafH, wrongRoot, 0, 1, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for root mismatch, got nil")
	}
}

func TestVerifyInclusionProof_NilResponse(t *testing.T) {
	err := VerifyInclusionProof(nil)
	if err == nil {
		t.Fatal("expected error for nil response")
	}
}

func TestVerifyInclusionProof_EmptyRootHash(t *testing.T) {
	leafH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse(leafH, "", 0, 1, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for empty rootHash")
	}
}

func TestVerifyInclusionProof_EmptyLeafHash(t *testing.T) {
	rootH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse("", rootH, 0, 1, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for empty leafHash")
	}
}

func TestVerifyInclusionProof_ZeroTreeSize(t *testing.T) {
	leafH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse(leafH, leafH, 0, 0, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for zero treeSize")
	}
}

func TestVerifyInclusionProof_LeafIndexOutOfRange(t *testing.T) {
	leafH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse(leafH, leafH, 5, 3, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for leafIndex out of range")
	}
}

func TestVerifyInclusionProof_InvalidHexRoot(t *testing.T) {
	leafH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse(leafH, "not-valid-hex!", 0, 1, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for invalid hex root")
	}
}

func TestVerifyInclusionProof_WrongRootLength(t *testing.T) {
	leafH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse(leafH, "abcd", 0, 1, []string{})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for wrong root hash length")
	}
}

func TestVerifyInclusionProof_InvalidPathHex(t *testing.T) {
	leafH := hexHash([]byte("data"))
	resp := buildMerkleTestResponse(leafH, leafH, 0, 2, []string{"invalid-hex!!!"})

	err := VerifyInclusionProof(resp)
	if err == nil {
		t.Fatal("expected error for invalid path hex")
	}
}
