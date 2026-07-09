package verify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// VerifyInclusionProof verifies the Merkle inclusion proof from the TL response.
// It uses the TL-provided leafHash as the starting point and walks the audit path
// (RFC 6962) to verify it reaches the rootHash.
func VerifyInclusionProof(resp *models.TLResponse) error {
	if resp == nil {
		return errors.New("merkle: nil TL response")
	}

	proof := &resp.MerkleProof

	if proof.RootHash == "" {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"rootHash is empty")
	}
	if proof.TreeSize <= 0 {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"treeSize must be positive")
	}
	if proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			fmt.Sprintf("leafIndex %d out of range [0, %d)", proof.LeafIndex, proof.TreeSize))
	}
	if proof.LeafHash == "" {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"leafHash is empty")
	}

	rootHash, err := hex.DecodeString(proof.RootHash)
	if err != nil {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"invalid rootHash hex", WithCause(err))
	}
	if len(rootHash) != sha256.Size {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			fmt.Sprintf("rootHash must be %d bytes, got %d", sha256.Size, len(rootHash)))
	}

	leafHash, err := hex.DecodeString(proof.LeafHash)
	if err != nil {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"invalid leafHash hex", WithCause(err))
	}
	if len(leafHash) != sha256.Size {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			fmt.Sprintf("leafHash must be %d bytes, got %d", sha256.Size, len(leafHash)))
	}

	// Decode audit path
	pathHashes := make([][]byte, len(proof.Path))
	for i, p := range proof.Path {
		h, decErr := hex.DecodeString(p)
		if decErr != nil {
			return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
				fmt.Sprintf("invalid path[%d] hex", i), WithCause(decErr))
		}
		if len(h) != sha256.Size {
			return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
				fmt.Sprintf("path[%d] must be %d bytes, got %d", i, sha256.Size, len(h)))
		}
		pathHashes[i] = h
	}

	// Walk the Merkle audit path (RFC 6962 / RFC 9162)
	computed := leafHash
	fn := uint64(proof.LeafIndex)
	sn := uint64(proof.TreeSize - 1)

	for _, sibling := range pathHashes {
		if sn == 0 {
			return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
				"excess audit path elements")
		}
		if fn%2 == 1 || fn == sn {
			computed = merkleNodeHash(sibling, computed)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			computed = merkleNodeHash(computed, sibling)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"insufficient audit path elements")
	}

	if subtle.ConstantTimeCompare(computed, rootHash) != 1 {
		return NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"computed root does not match rootHash")
	}

	return nil
}

// merkleNodeHash computes SHA-256(0x01 || left || right) for interior nodes.
func merkleNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01}) // RFC 6962 interior node prefix
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
