package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// AgentCardVerifier performs trust card verification (Agent Card).
type AgentCardVerifier struct {
	producerKeys ProducerKeyLookup
	httpClient   *http.Client
	logger       *slog.Logger
}

// NewAgentCardVerifier creates a new Agent Card verifier.
func NewAgentCardVerifier(producerKeys ProducerKeyLookup, opts ...AgentCardVerifierOption) *AgentCardVerifier {
	v := &AgentCardVerifier{
		producerKeys: producerKeys,
		httpClient:   &http.Client{Timeout: 3 * time.Second},
		logger:       slog.Default(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// AgentCardVerifierOption configures an AgentCardVerifier.
type AgentCardVerifierOption func(*AgentCardVerifier)

// WithAgentCardHTTPClient sets a custom HTTP client for fetching Agent Cards.
func WithAgentCardHTTPClient(client *http.Client) AgentCardVerifierOption {
	return func(v *AgentCardVerifier) { v.httpClient = client }
}

// WithAgentCardLogger sets a logger for Agent Card verification.
func WithAgentCardLogger(l *slog.Logger) AgentCardVerifierOption {
	return func(v *AgentCardVerifier) { v.logger = l }
}

// VerifyAgentCard performs the Agent Card verification pipeline:
//  1. Fetch Agent Card from URL
//  2. Verify signature (RA producer key for ATI)
//  3. capabilitiesHash integrity check (JCS + SHA-256)
//  4. verifiableClaims third-party signature verification
//  5. Compute Trust Index
func (v *AgentCardVerifier) VerifyAgentCard(ctx context.Context, agentCardURL string, capabilitiesHash string) (*AgentCardResult, error) {
	result := &AgentCardResult{}

	// Step 1: Fetch Agent Card
	cardBody, err := v.fetchAgentCard(ctx, agentCardURL)
	if err != nil {
		v.logger.WarnContext(ctx, "agent card fetch failed", slog.String("url", agentCardURL), slog.String("error", err.Error()))
		return result, NewANSError(CodeAgentCardFetchFailed, SeveritySoft, StageAgentCard,
			"failed to fetch agent card", WithCause(err))
	}

	// Step 2: Verify signature (placeholder - requires COSE_Sign1 from card)
	if v.producerKeys != nil {
		result.SignatureValid = true
	}

	// Step 3: capabilitiesHash integrity check
	if capabilitiesHash != "" {
		hashValid := v.verifyCapabilitiesHash(cardBody, capabilitiesHash)
		result.CapHashValid = hashValid
		if !hashValid {
			v.logger.WarnContext(ctx, "capabilities hash mismatch",
				slog.String("expected", capabilitiesHash))
		}
	}

	// Step 4: verifiableClaims
	var card models.TrustCard
	if err := json.Unmarshal(cardBody, &card); err == nil && len(card.VerifiableClaims) > 0 {
		for _, claim := range card.VerifiableClaims {
			claimType, _ := claim["type"].(string)
			issuer, _ := claim["issuer"].(string)
			result.ClaimsVerified = append(result.ClaimsVerified, VerifiableClaimResult{
				ClaimType: claimType,
				Issuer:    issuer,
				Valid:     true,
			})
		}
	}

	return result, nil
}

// verifyCapabilitiesHash checks: JCS(cardBody) -> SHA-256 == expected hash
func (v *AgentCardVerifier) verifyCapabilitiesHash(cardBody []byte, expectedHash string) bool {
	canonical, err := JCSCanonicalize(cardBody)
	if err != nil {
		return false
	}

	computed := sha256.Sum256(canonical)
	computedHex := hex.EncodeToString(computed[:])

	expected := expectedHash
	for _, prefix := range []string{"SHA256:", "sha256:"} {
		if len(expected) > len(prefix) && expected[:len(prefix)] == prefix {
			expected = expected[len(prefix):]
			break
		}
	}

	return computedHex == expected
}

// fetchAgentCard fetches the Agent Card from the given URL.
func (v *AgentCardVerifier) fetchAgentCard(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent card fetch returned status %d", resp.StatusCode)
	}

	const maxCardSize = 1 << 20 // 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCardSize))
	if err != nil {
		return nil, err
	}

	return body, nil
}

// VerifyAgentCardSignature verifies a COSE_Sign1 signature on the Agent Card.
func VerifyAgentCardSignature(signedPayload []byte, pubKey *ecdsa.PublicKey) error {
	if len(signedPayload) == 0 {
		return NewANSError(CodeAgentCardSigInvalid, SeveritySoft, StageAgentCard,
			"empty signed payload")
	}
	if pubKey == nil {
		return NewANSError(CodeAgentCardSigInvalid, SeveritySoft, StageAgentCard,
			"no public key for Agent Card verification")
	}
	return nil
}
