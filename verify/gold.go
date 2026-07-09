package verify

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

const defaultCNNICTLBaseURL = "https://tl.ansagent.cn:8180/ans/api/v1"

// GoldVerifierConfig configures the Gold verification behavior.
type GoldVerifierConfig struct {
	TLBaseURL    string
	TLPublicKey  *ecdsa.PublicKey
	ProducerKeys ProducerKeyLookup
	DNSResolver  DNSResolver
	TLogClient   TransparencyLogClient
	TrustPolicy  *TrustPolicy
	Logger       *slog.Logger
}

// VerifyGold performs full Gold-level verification against the Transparency Log.
// Steps: DNS discovery -> fetch TLResponse -> verify seal signature ->
// verify inclusion proof -> verify producer signature -> fingerprint match -> status check.
func VerifyGold(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, cfg *GoldVerifierConfig) *VerificationResult {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	tlBaseURL := cfg.TLBaseURL
	if tlBaseURL == "" {
		tlBaseURL = defaultCNNICTLBaseURL
	}

	ansName := fmt.Sprintf("ati://%s", fqdn.String())

	// Step 1: DNS Discovery
	log.DebugContext(ctx, "gold: DNS discovery", slog.String("fqdn", fqdn.String()))
	result, err := cfg.DNSResolver.LookupATIDiscovery(ctx, fqdn)
	if err != nil {
		return NewFailureResult(ansName, NewANSError(CodeDNSCoreRecordMissing, SeverityHard, StageDNSDiscovery,
			fmt.Sprintf("DNS discovery failed for %s", fqdn), WithCause(err)))
	}
	if !result.Found || len(result.Records) == 0 {
		return NewFailureResult(ansName, NewANSError(CodeDNSCoreRecordMissing, SeverityHard, StageDNSDiscovery,
			fmt.Sprintf("no _ati records found for %s", fqdn)))
	}
	agentID := result.Records[0].ID
	if agentID == "" {
		return NewFailureResult(ansName, NewANSError(CodeDNSCoreRecordMissing, SeverityHard, StageDNSDiscovery,
			fmt.Sprintf("_ati record for %s has no agent ID", fqdn)))
	}

	// Step 2: Fetch TL Response
	tlURL := fmt.Sprintf("%s/tl/agents/%s/logs/latest", tlBaseURL, agentID)
	log.DebugContext(ctx, "gold: fetching TL response", slog.String("url", tlURL))
	tlResp, err := cfg.TLogClient.FetchTLResponse(ctx, tlURL)
	if err != nil {
		return NewFailureResult(ansName, NewANSError(CodeTLUnreachable, SeveritySoft, StageTLVerify,
			"TL fetch failed", WithCause(err)))
	}

	// Step 3: Verify Seal Signature
	log.DebugContext(ctx, "gold: verifying seal signature")
	if err := VerifySealSignature(tlResp, cfg.TLPublicKey); err != nil {
		return NewFailureResult(ansName, NewANSError(CodeTLReceiptSigInvalid, SeverityHard, StageTLVerify,
			"seal signature verification failed", WithCause(err)))
	}

	// Step 4: Verify Inclusion Proof (Merkle)
	log.DebugContext(ctx, "gold: verifying inclusion proof")
	if err := VerifyInclusionProof(tlResp); err != nil {
		return NewFailureResult(ansName, NewANSError(CodeTLInclusionProofFailed, SeverityHard, StageTLVerify,
			"inclusion proof verification failed", WithCause(err)))
	}

	// Step 5: Verify Producer Signature (optional based on EvidenceRef.SignatureRequired)
	log.DebugContext(ctx, "gold: verifying producer signature")
	if cfg.ProducerKeys != nil {
		if err := VerifyProducerSignature(tlResp, cfg.ProducerKeys); err != nil {
			return NewFailureResult(ansName, NewANSError(CodeProducerSigInvalid, SeverityHard, StageTLVerify,
				"producer signature verification failed", WithCause(err)))
		}
	}

	// Step 6: Certificate Fingerprint Cross-Match
	log.DebugContext(ctx, "gold: matching certificate fingerprint")
	if !matchFingerprint(tlResp, cert) {
		return NewFailureResult(ansName, NewANSError(CodeTLFingerprintMismatch, SeverityHard, StageTLVerify,
			"certificate fingerprint does not match TL attestation",
			WithEvidence(map[string]string{
				"expected_identity": tlResp.Payload.IdentityCertFingerprint(),
				"expected_server":   tlResp.Payload.ServerCertFingerprint(),
				"actual":            cert.Fingerprint.String(),
			})))
	}

	// Step 7: Status Check (from payload.agentStatus)
	status := models.TLAgentStatus(strings.ToUpper(tlResp.Payload.AgentStatus))
	if status.IsTerminal() {
		code := CodeStatusRevoked
		if status == models.TLStatusExpired {
			code = CodeStatusExpired
		}
		return NewFailureResult(ansName, NewANSError(code, SeverityHard, StageTLVerify,
			fmt.Sprintf("agent status %s does not allow connections", status)))
	}

	// Build trust index
	params := TrustIndexParams{
		IdentityVerified:  true,
		TLReceiptVerified: true,
		ProducerSigValid:  cfg.ProducerKeys != nil,
		MerkleProofValid:  true,
		FingerprintMatch:  true,
		StatusActive:      status == models.TLStatusActive,
	}
	trustIndex, trustLevel := ComputeTrustIndex(params)

	log.InfoContext(ctx, "gold: verification succeeded",
		slog.String("fqdn", fqdn.String()),
		slog.String("agentId", agentID),
		slog.String("status", string(status)),
		slog.Int("trustIndex", trustIndex))

	vr := NewSuccessResult(ansName, trustIndex, trustLevel)
	vr.Status = string(status)
	if status == models.TLStatusWarning {
		vr.Warnings = append(vr.Warnings, "agent status is WARNING")
	}
	if status == models.TLStatusDeprecated {
		vr.Warnings = append(vr.Warnings, "agent status is DEPRECATED")
	}

	return vr
}

// matchFingerprint checks the peer certificate fingerprint against TL payload certificates.
func matchFingerprint(tlResp *models.TLResponse, cert *CertIdentity) bool {
	idFP := tlResp.Payload.IdentityCertFingerprint()
	if idFP != "" && cert.Fingerprint.Matches(idFP) {
		return true
	}
	srvFP := tlResp.Payload.ServerCertFingerprint()
	if srvFP != "" && cert.Fingerprint.Matches(srvFP) {
		return true
	}
	return false
}
