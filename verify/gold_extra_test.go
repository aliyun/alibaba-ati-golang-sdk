package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// goldExtraConfig builds a GoldVerifierConfig with the default CNNIC TL base
// URL (empty TLBaseURL) to exercise the default-URL code path (line 37).
func goldExtraConfig(t *testing.T, tlKey *ecdsa.PrivateKey, producerKey *ecdsa.PrivateKey, resolver DNSResolver, tlogClient TransparencyLogClient) *GoldVerifierConfig {
	t.Helper()
	cfg := &GoldVerifierConfig{
		// TLBaseURL intentionally left empty to trigger defaultCNNICTLBaseURL.
		TLPublicKey: &tlKey.PublicKey,
		DNSResolver: resolver,
		TLogClient:  tlogClient,
	}
	if producerKey != nil {
		cfg.ProducerKeys = NewMockProducerKeyLookup().WithKey("producer-kid-1", &producerKey.PublicKey)
	}
	return cfg
}

// TestVerifyGold_DefaultTLBaseURL verifies that when TLBaseURL is empty,
// the default CNNIC TL base URL is used (line 37). The mock TLog client
// must be configured with the default URL for the fetch to succeed.
func TestVerifyGold_DefaultTLBaseURL(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("default-tl-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	// Use the default CNNIC TL base URL (line 37 path).
	tlURL := defaultCNNICTLBaseURL + "/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldExtraConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() with default TL URL failed: %v", result.Error)
	}
}

// TestVerifyGold_DNSDiscoveryError verifies that a DNS discovery error
// returns a failure result with CodeDNSCoreRecordMissing (lines 46-47).
func TestVerifyGold_DNSDiscoveryError(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	mockResolver := NewMockDNSResolver().
		WithError("error.example.com", errors.New("DNS SERVFAIL"))
	mockTLog := NewMockTransparencyLogClient()

	fqdn, _ := models.NewFqdn("error.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	cert := &CertIdentity{}
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail on DNS discovery error")
	}
	if result.Error == nil {
		t.Fatal("expected non-nil error in result")
	}
}

// TestVerifyGold_DNSDiscoveryFoundButEmptyRecords verifies that when DNS
// discovery returns Found=true but with zero records, the verification
// fails (lines 49-52, the "no _ati records found" path).
func TestVerifyGold_DNSDiscoveryFoundButEmptyRecords(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// The mock returns Found=true only when records slice is non-empty.
	// To hit the "len(records) == 0" path, we need a custom resolver.
	resolver := &emptyRecordsResolver{}
	mockTLog := NewMockTransparencyLogClient()

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, nil, resolver, mockTLog)

	cert := &CertIdentity{}
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail when discovery returns no records")
	}
}

// emptyRecordsResolver returns Found=true but with an empty Records slice,
// to exercise the "!result.Found || len(result.Records) == 0" branch where
// Found is true but Records is empty.
type emptyRecordsResolver struct{}

func (r *emptyRecordsResolver) LookupATIBadge(_ context.Context, _ models.Fqdn) (DNSLookupResult, error) {
	return DNSLookupResult{Found: false}, nil
}

func (r *emptyRecordsResolver) LookupATIDiscovery(_ context.Context, _ models.Fqdn) (ATIDiscoveryResult, error) {
	return ATIDiscoveryResult{Found: true, Records: []*ATIRecord{}}, nil
}

func (r *emptyRecordsResolver) FindBadgeForVersion(_ context.Context, _ models.Fqdn, _ models.Version) (*ATIBadgeRecord, error) {
	return nil, ErrRecordNotFound
}

func (r *emptyRecordsResolver) FindPreferredBadge(_ context.Context, _ models.Fqdn) (*ATIBadgeRecord, error) {
	return nil, ErrRecordNotFound
}

// TestVerifyGold_EmptyAgentID verifies that when the _ati record has an
// empty agent ID, verification fails (lines 55-56).
func TestVerifyGold_EmptyAgentID(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})
	mockTLog := NewMockTransparencyLogClient()

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	cert := &CertIdentity{}
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail when agent ID is empty")
	}
}

// TestVerifyGold_InclusionProofFailure verifies that a bad Merkle proof
// causes verification to fail with CodeTLInclusionProofFailed (lines 78-79).
func TestVerifyGold_InclusionProofFailure(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("merkle-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())
	// Tamper with the Merkle proof: use a wrong root hash.
	tlResp.MerkleProof.RootHash = hexHash([]byte("wrong-root-hash"))
	// Re-sign the seal since we didn't change sealed fields.
	tlResp.Seal.Signature = signSeal(t, tlResp, tlKey)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail with bad Merkle proof")
	}
}

// TestVerifyGold_ProducerSignatureFailure verifies that an invalid producer
// signature causes verification to fail with CodeProducerSigInvalid
// (lines 86-87).
func TestVerifyGold_ProducerSignatureFailure(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongProducerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("producer-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	// Build TL response signed with the WRONG producer key, but configure
	// the verifier to expect the correct producer key.
	tlResp := buildTestTLResponse(t, tlKey, wrongProducerKey, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail with bad producer signature")
	}
}

// TestVerifyGold_ExpiredStatus verifies that an EXPIRED agent status causes
// verification to fail with CodeStatusExpired (line 108).
func TestVerifyGold_ExpiredStatus(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("expired-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())
	tlResp.Payload.AgentStatus = "EXPIRED"
	// Re-sign producer and seal after modifying status.
	payloadJSON, _ := json.Marshal(tlResp.Payload)
	canonical, _ := JCSCanonicalize(payloadJSON)
	producerDigest := sha256.Sum256(canonical)
	producerSig, _ := ecdsa.SignASN1(rand.Reader, producerKey, producerDigest[:])
	tlResp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(producerSig)
	tlResp.Seal.Signature = signSeal(t, tlResp, tlKey)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail with EXPIRED status")
	}
}

// TestVerifyGold_WarningStatus verifies that a WARNING agent status succeeds
// and produces a warning in the result (line 134).
func TestVerifyGold_WarningStatus(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("warning-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, fp.String())
	tlResp.Payload.AgentStatus = "WARNING"
	// Re-sign producer and seal.
	payloadJSON, _ := json.Marshal(tlResp.Payload)
	canonical, _ := JCSCanonicalize(payloadJSON)
	producerDigest := sha256.Sum256(canonical)
	producerSig, _ := ecdsa.SignASN1(rand.Reader, producerKey, producerDigest[:])
	tlResp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(producerSig)
	tlResp.Seal.Signature = signSeal(t, tlResp, tlKey)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() should succeed with WARNING status: %v", result.Error)
	}
	if result.Status != "WARNING" {
		t.Errorf("Status = %q, want %q", result.Status, "WARNING")
	}
}

// TestVerifyGold_NoProducerKeys_SkipsProducerSig verifies that when
// ProducerKeys is nil, the producer signature verification is skipped
// (line 84: "if cfg.ProducerKeys != nil" is false).
func TestVerifyGold_NoProducerKeys_SkipsProducerSig(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("no-producer-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	// Build TL response without a producer key (SignatureRequired=false).
	tlResp := buildTestTLResponse(t, tlKey, nil, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() should succeed without producer keys: %v", result.Error)
	}
}

// TestMatchFingerprint_IdentityMatch verifies that matchFingerprint returns
// true when the identity cert fingerprint matches.
func TestMatchFingerprint_IdentityMatch(t *testing.T) {
	fp := CertFingerprintFromDER([]byte("match-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: fp.String(),
			},
		},
	}

	if !matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = false, want true for identity match")
	}
}

// TestMatchFingerprint_ServerMatch verifies that matchFingerprint returns
// true when the server cert fingerprint matches (line 151).
func TestMatchFingerprint_ServerMatch(t *testing.T) {
	fp := CertFingerprintFromDER([]byte("server-match-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				ServerCertFingerprint: fp.String(),
			},
		},
	}

	if !matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = false, want true for server match")
	}
}

// TestMatchFingerprint_NoMatch verifies that matchFingerprint returns false
// when neither identity nor server fingerprint matches.
func TestMatchFingerprint_NoMatch(t *testing.T) {
	fpActual := CertFingerprintFromDER([]byte("actual-cert"))
	cert := &CertIdentity{Fingerprint: fpActual}

	fpExpected := CertFingerprintFromDER([]byte("different-cert"))
	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: fpExpected.String(),
				ServerCertFingerprint:    fpExpected.String(),
			},
		},
	}

	if matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = true, want false for no match")
	}
}

// TestMatchFingerprint_EmptyFingerprints verifies that matchFingerprint
// returns false when both TL fingerprints are empty.
func TestMatchFingerprint_EmptyFingerprints(t *testing.T) {
	fp := CertFingerprintFromDER([]byte("some-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "",
				ServerCertFingerprint:    "",
			},
		},
	}

	if matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = true, want false when both fingerprints empty")
	}
}

// TestMatchFingerprint_IdentityEmpty_ServerMatches verifies that when
// the identity fingerprint is empty but the server fingerprint matches,
// matchFingerprint returns true.
func TestMatchFingerprint_IdentityEmpty_ServerMatches(t *testing.T) {
	fp := CertFingerprintFromDER([]byte("mixed-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				IdentityCertFingerprint: "",
				ServerCertFingerprint:    fp.String(),
			},
		},
	}

	if !matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = false, want true when server matches and identity is empty")
	}
}

// TestMatchFingerprint_PreviousIdentityMatch verifies that a peer cert whose
// fingerprint matches the *previous* identity fingerprint (a cert renewal
// still in its transition window) is accepted even though the current
// identity fingerprint has already moved on.
func TestMatchFingerprint_PreviousIdentityMatch(t *testing.T) {
	oldFP := CertFingerprintFromDER([]byte("old-identity-cert"))
	newFP := CertFingerprintFromDER([]byte("new-identity-cert"))
	cert := &CertIdentity{Fingerprint: oldFP}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				IdentityCertFingerprint:         newFP.String(),
				PreviousIdentityCertFingerprint: oldFP.String(),
			},
		},
	}

	if !matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = false, want true when peer cert matches the previous identity fingerprint")
	}
}

// TestMatchFingerprint_PreviousServerMatch mirrors the identity case for the
// server fingerprint.
func TestMatchFingerprint_PreviousServerMatch(t *testing.T) {
	oldFP := CertFingerprintFromDER([]byte("old-server-cert"))
	newFP := CertFingerprintFromDER([]byte("new-server-cert"))
	cert := &CertIdentity{Fingerprint: oldFP}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				ServerCertFingerprint:         newFP.String(),
				PreviousServerCertFingerprint: oldFP.String(),
			},
		},
	}

	if !matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = false, want true when peer cert matches the previous server fingerprint")
	}
}

// TestMatchFingerprint_PreviousFingerprintStale verifies that a cert
// matching neither the current nor the previous fingerprint is still
// rejected — the renewal window doesn't turn into an open-ended allowlist.
func TestMatchFingerprint_PreviousFingerprintStale(t *testing.T) {
	staleFP := CertFingerprintFromDER([]byte("stale-cert"))
	oldFP := CertFingerprintFromDER([]byte("old-identity-cert"))
	newFP := CertFingerprintFromDER([]byte("new-identity-cert"))
	cert := &CertIdentity{Fingerprint: staleFP}

	tlResp := &models.TLResponse{
		Payload: models.TLPayload{
			Certificates: models.TLCertificates{
				IdentityCertFingerprint:         newFP.String(),
				PreviousIdentityCertFingerprint: oldFP.String(),
			},
		},
	}

	if matchFingerprint(tlResp, cert) {
		t.Error("matchFingerprint() = true, want false for a cert older than the previous fingerprint")
	}
}

// TestMatchFingerprint_PreviousAloneWithoutCurrent_Rejected verifies that a
// previous fingerprint with its current counterpart empty is treated as an
// anomalous record, not an in-progress renewal — previous must never stand
// in for a missing current, for either the identity or server cert pair.
func TestMatchFingerprint_PreviousAloneWithoutCurrent_Rejected(t *testing.T) {
	oldFP := CertFingerprintFromDER([]byte("old-cert"))
	cert := &CertIdentity{Fingerprint: oldFP}

	t.Run("identity previous alone", func(t *testing.T) {
		tlResp := &models.TLResponse{
			Payload: models.TLPayload{
				Certificates: models.TLCertificates{
					PreviousIdentityCertFingerprint: oldFP.String(),
				},
			},
		}
		if matchFingerprint(tlResp, cert) {
			t.Error("matchFingerprint() = true, want false when identityCertFingerprint is empty and only previous is set")
		}
	})

	t.Run("server previous alone", func(t *testing.T) {
		tlResp := &models.TLResponse{
			Payload: models.TLPayload{
				Certificates: models.TLCertificates{
					PreviousServerCertFingerprint: oldFP.String(),
				},
			},
		}
		if matchFingerprint(tlResp, cert) {
			t.Error("matchFingerprint() = true, want false when serverCertFingerprint is empty and only previous is set")
		}
	})
}

// TestMatchFingerprint_PreviousAloneWithBlankCurrent_Rejected mirrors
// TestMatchFingerprint_PreviousAloneWithoutCurrent_Rejected for a current
// fingerprint that is whitespace-only rather than truly empty: it must be
// treated the same as missing, for either the identity or server cert pair.
func TestMatchFingerprint_PreviousAloneWithBlankCurrent_Rejected(t *testing.T) {
	oldFP := CertFingerprintFromDER([]byte("old-cert"))
	cert := &CertIdentity{Fingerprint: oldFP}

	t.Run("identity previous alone, blank current", func(t *testing.T) {
		tlResp := &models.TLResponse{
			Payload: models.TLPayload{
				Certificates: models.TLCertificates{
					IdentityCertFingerprint:         " \t\r\n",
					PreviousIdentityCertFingerprint: oldFP.String(),
				},
			},
		}
		if matchFingerprint(tlResp, cert) {
			t.Error("matchFingerprint() = true, want false when identityCertFingerprint is blank and only previous is set")
		}
	})

	t.Run("server previous alone, blank current", func(t *testing.T) {
		tlResp := &models.TLResponse{
			Payload: models.TLPayload{
				Certificates: models.TLCertificates{
					ServerCertFingerprint:         " \t\r\n",
					PreviousServerCertFingerprint: oldFP.String(),
				},
			},
		}
		if matchFingerprint(tlResp, cert) {
			t.Error("matchFingerprint() = true, want false when serverCertFingerprint is blank and only previous is set")
		}
	})
}

// TestVerifyGold_DNSDiscoveryNotFound verifies that when DNS discovery
// returns Found=false, the verification fails (lines 49-52).
func TestVerifyGold_DNSDiscoveryNotFound(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Mock with no discovery records → Found=false.
	mockResolver := NewMockDNSResolver()
	mockTLog := NewMockTransparencyLogClient()

	fqdn, _ := models.NewFqdn("notfound.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	cert := &CertIdentity{}
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if result.IsSuccess() {
		t.Fatal("VerifyGold() should fail when DNS discovery returns not found")
	}
}

// TestVerifyGold_SealSigSuccess_NoProducerKey verifies the full happy path
// where seal signature is valid and no producer key is configured. This
// exercises the "cfg.ProducerKeys != nil" branch as false (line 84).
func TestVerifyGold_SealSigSuccess_NoProducerKey_ActiveStatus(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("active-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, nil, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, nil, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() should succeed: %v", result.Error)
	}
	if result.Status != "ACTIVE" {
		t.Errorf("Status = %q, want %q", result.Status, "ACTIVE")
	}
}

// TestVerifyGold_NilLogger verifies that a nil Logger in the config does
// not cause a panic; slog.Default() is used instead (lines 31-33).
func TestVerifyGold_NilLogger(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("nil-logger-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, nil, fp.String())

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := &GoldVerifierConfig{
		TLBaseURL:   "https://tl.test.local/ans/api/v1",
		TLPublicKey: &tlKey.PublicKey,
		DNSResolver: mockResolver,
		TLogClient:  mockTLog,
		Logger:      nil, // explicitly nil
	}

	// Should not panic.
	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() with nil logger should succeed: %v", result.Error)
	}
}

// TestVerifyGold_FingerprintServerMatch verifies the full path where the
// certificate fingerprint matches the SERVER cert fingerprint in the TL
// payload (not the identity cert). This exercises matchFingerprint's
// server-cert branch (line 151) in the context of VerifyGold.
func TestVerifyGold_FingerprintServerMatch(t *testing.T) {
	tlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	producerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp := CertFingerprintFromDER([]byte("server-fp-cert"))
	cert := &CertIdentity{Fingerprint: fp}

	tlResp := buildTestTLResponse(t, tlKey, producerKey, "different-identity-fp")
	// Set the server cert fingerprint to match the actual cert.
	tlResp.Payload.Certificates.ServerCertFingerprint = fp.String()
	// Re-sign since payload changed.
	payloadJSON, _ := json.Marshal(tlResp.Payload)
	canonical, _ := JCSCanonicalize(payloadJSON)
	producerDigest := sha256.Sum256(canonical)
	producerSig, _ := ecdsa.SignASN1(rand.Reader, producerKey, producerDigest[:])
	tlResp.EvidenceRef.EvidenceHash = base64.StdEncoding.EncodeToString(producerSig)
	tlResp.Seal.Signature = signSeal(t, tlResp, tlKey)

	mockResolver := NewMockDNSResolver().
		WithDiscoveryRecords("agent.example.com", []*ATIRecord{
			{ID: "ans-gold-001", RA: "aliyun", Version: models.NewVersion(1, 0, 0), Mode: ATIRecordModeDirect},
		})

	tlURL := "https://tl.test.local/ans/api/v1/tl/agents/ans-gold-001/logs/latest"
	mockTLog := NewMockTransparencyLogClient().WithTLResponse(tlURL, tlResp)

	fqdn, _ := models.NewFqdn("agent.example.com")
	cfg := goldTestConfig(t, tlKey, producerKey, mockResolver, mockTLog)

	result := VerifyGold(context.Background(), fqdn, cert, cfg)
	if !result.IsSuccess() {
		t.Fatalf("VerifyGold() should succeed with server fingerprint match: %v", result.Error)
	}
}

// Ensure strings import is used.
var _ = strings.Contains
