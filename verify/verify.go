package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify/scitt"
)

// certRole distinguishes how a certificate should be matched against a SCITT status token.
// ServerVerifier passes roleServer (only server cert arrays are consulted); ClientVerifier
// passes roleIdentity (only identity cert arrays are consulted). This prevents a
// compromised identity-cert key from impersonating a server (or vice versa).
type certRole int

const (
	roleServer certRole = iota
	roleIdentity
)

// applyFailurePolicy applies the configured failure policy when DNS or TLog errors occur.
// For FailClosed, returns the original error outcome.
// For FailOpenWithCache, checks stale cache entries.
// For FailOpen, returns a pass-through outcome.
//
// NOTE: This policy does NOT apply to SCITT verification failures — a malformed
// or signature-invalid SCITT artifact is always terminal to prevent forgery
// acceptance under FailOpen.
func applyFailurePolicy(config *verifierConfig, fqdn models.Fqdn, version *models.Version, errorOutcome *VerificationOutcome) *VerificationOutcome {
	switch config.failurePolicy {
	case FailClosed:
		return errorOutcome
	case FailOpenWithCache:
		return applyFailOpenWithCache(config, fqdn, version, errorOutcome)
	case FailOpen:
		return NewFailOpenOutcome(errorOutcome.Error)
	}
	return errorOutcome
}

// applyFailOpenWithCache attempts to use a stale cached TL response for fail-open-with-cache policy.
func applyFailOpenWithCache(config *verifierConfig, fqdn models.Fqdn, version *models.Version, errorOutcome *VerificationOutcome) *VerificationOutcome {
	if config.cache == nil {
		return errorOutcome
	}

	maxStale := config.failurePolicyConfig.MaxStaleness
	if version != nil {
		if cached, ok := config.cache.GetStaleByFqdnVersion(fqdn, *version, maxStale); ok {
			return &VerificationOutcome{Type: OutcomeFailOpen, TLResponse: cached.TLResponse}
		}
	} else {
		if cached, ok := config.cache.GetStaleByFqdn(fqdn, maxStale); ok {
			return &VerificationOutcome{Type: OutcomeFailOpen, TLResponse: cached.TLResponse}
		}
	}
	return errorOutcome
}

// defaultDANEPort is the standard HTTPS port used for DANE/TLSA lookups.
const defaultDANEPort = 443

// verifyDANE performs an optional DANE/TLSA check if a DANEResolver is configured.
// Returns nil if DANE is not configured, passes, or should be skipped.
// Returns an error outcome only if DANE explicitly rejects (mismatch or DNSSEC failure).
func verifyDANE(ctx context.Context, config *verifierConfig, fqdn models.Fqdn, cert *CertIdentity, outcome *VerificationOutcome) *VerificationOutcome {
	if config.daneResolver == nil {
		return nil
	}

	daneVerifier := NewDANEVerifier(config.daneResolver)
	daneOutcome := daneVerifier.Verify(ctx, fqdn, defaultDANEPort, cert)

	if daneOutcome.IsReject() {
		return NewDANERejectionOutcome(outcome.TLResponse, daneOutcome)
	}

	// DANE passed, skipped, no records, or lookup error — add info to outcome
	if daneOutcome.IsPass() && daneOutcome.Type == DANEVerified {
		outcome.DANEOutcome = daneOutcome
	}

	return nil
}

// rewriteTLHost replaces the hostname in a badge URL with the configured
// trusted TL host. If rewriting fails, the original URL is returned unchanged.
func rewriteTLHost(config *verifierConfig, rawURL string, log *slog.Logger) string {
	if config.trustedTLHost == "" {
		return rawURL
	}
	rewritten, err := RewriteBadgeURLHost(rawURL, config.trustedTLHost)
	if err != nil {
		log.Warn("rewriteTLHost: failed to rewrite badge URL, using original",
			slog.String("url", rawURL), slog.String("error", err.Error()))
		return rawURL
	}
	return rewritten
}

// ServerVerifier verifies server certificates against the ANS transparency log.
// Use this when a client wants to verify that a server is a legitimate ANS agent.
type ServerVerifier struct {
	config *verifierConfig
}

// NewServerVerifier creates a new server verifier with the given options.
func NewServerVerifier(opts ...Option) *ServerVerifier {
	config := defaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return &ServerVerifier{config: config}
}

// Verify verifies a server certificate for the given FQDN.
func (v *ServerVerifier) Verify(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) *VerificationOutcome {
	log := configLogger(v.config)

	// 1. Check cache first
	if v.config.cache != nil {
		if cached, ok := v.config.cache.GetByFqdn(fqdn); ok {
			log.DebugContext(ctx, "TL verification: cache check",
				slog.String("fqdn", fqdn.String()), slog.Bool("cache_hit", true))
			result := v.verifyWithTLResponse(cached.TLResponse, cert, fqdn)
			if result.Type != OutcomeFingerprintMismatch {
				if rejection := v.applyDANE(ctx, fqdn, cert, result); rejection != nil {
					return rejection
				}
				return result
			}
		} else {
			log.DebugContext(ctx, "TL verification: cache check",
				slog.String("fqdn", fqdn.String()), slog.Bool("cache_hit", false))
		}
	}

	// 2. Fetch TL response from DNS + TLog
	tlResp, outcome := v.fetchTLResponse(ctx, fqdn)
	if outcome != nil {
		return outcome
	}

	// 3. Cache the TL response
	if v.config.cache != nil {
		v.config.cache.Insert(fqdn, tlResp)
	}

	// 4. Verify against TL response
	outcome = v.verifyWithTLResponse(tlResp, cert, fqdn)
	if rejection := v.applyDANE(ctx, fqdn, cert, outcome); rejection != nil {
		return rejection
	}
	return outcome
}

// applyDANE runs an optional DANE/TLSA check when the badge outcome succeeded
// and a DANE resolver is configured. It returns a rejection outcome if DANE
// affirmatively rejects; otherwise it enriches outcome in place and returns nil.
func (v *ServerVerifier) applyDANE(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, outcome *VerificationOutcome) *VerificationOutcome {
	if outcome.Type != OutcomeVerified {
		return nil
	}
	return verifyDANE(ctx, v.config, fqdn, cert, outcome)
}

// Prefetch fetches and caches a TL response for an FQDN.
// Returns immediately if a fresh cached entry exists.
func (v *ServerVerifier) Prefetch(ctx context.Context, fqdn models.Fqdn) (*models.TLResponse, error) {
	if v.config.cache != nil {
		if cached, ok := v.config.cache.GetByFqdn(fqdn); ok {
			return cached.TLResponse, nil
		}
	}

	tlResp, outcome := v.fetchTLResponse(ctx, fqdn)
	if outcome != nil {
		return nil, outcome.ToError()
	}

	if v.config.cache != nil {
		v.config.cache.Insert(fqdn, tlResp)
	}

	return tlResp, nil
}

// VerifyWithScitt verifies a server certificate using SCITT receipts and status tokens.
// If headers are empty or nil, delegates to the standard badge-based Verify().
// If SCITT verification encounters a fallback-eligible transport error, falls back to badge.
func (v *ServerVerifier) VerifyWithScitt(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	log := configLogger(v.config)

	// Empty headers → badge path
	if headers == nil || headers.IsEmpty() {
		log.InfoContext(ctx, "VerifyWithScitt: no SCITT headers, falling back to badge",
			slog.String("fqdn", fqdn.String()))
		return v.Verify(ctx, fqdn, cert)
	}

	// Both required per spec
	if !headers.HasBoth() {
		log.WarnContext(ctx, "VerifyWithScitt: partial SCITT headers, rejecting",
			slog.String("fqdn", fqdn.String()),
			slog.Bool("has_receipt", len(headers.Receipt) > 0),
			slog.Bool("has_token", len(headers.StatusToken) > 0))
		return NewScittErrorOutcome(errors.New("both X-SCITT-Receipt and X-ANS-Status-Token headers are required"))
	}

	return verifyWithHeaders(ctx, v.config, fqdn, cert, headers, log, roleServer,
		func() *VerificationOutcome { return v.Verify(ctx, fqdn, cert) })
}

// fetchTLResponse fetches a TL response from DNS and TLog.
func (v *ServerVerifier) fetchTLResponse(ctx context.Context, fqdn models.Fqdn) (*models.TLResponse, *VerificationOutcome) {
	log := configLogger(v.config)

	log.DebugContext(ctx, "fetchTLResponse: DNS lookup", slog.String("fqdn", fqdn.String()))
	record, err := v.config.dnsResolver.FindPreferredBadge(ctx, fqdn)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			return nil, NewNotATIAgentOutcome(fqdn.String())
		}
		log.WarnContext(ctx, "fetchTLResponse: DNS error",
			slog.String("fqdn", fqdn.String()), slog.String("error", err.Error()))
		outcome := NewDNSErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, nil, outcome)
	}
	if record == nil {
		return nil, NewNotATIAgentOutcome(fqdn.String())
	}

	tlURL := rewriteTLHost(v.config, record.URL, log)

	log.DebugContext(ctx, "fetchTLResponse: fetching", slog.String("url", tlURL))
	tlResp, err := v.config.tlogClient.FetchTLResponse(ctx, tlURL)
	if err != nil {
		log.WarnContext(ctx, "fetchTLResponse: TLog error",
			slog.String("url", tlURL), slog.String("error", err.Error()))
		outcome := NewTlogErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, nil, outcome)
	}

	return tlResp, nil
}

// verifyWithTLResponse verifies a certificate against a TL response.
func (v *ServerVerifier) verifyWithTLResponse(tlResp *models.TLResponse, cert *CertIdentity, fqdn models.Fqdn) *VerificationOutcome {
	status := models.TLAgentStatus(tlResp.Payload.AgentStatus)
	if !status.IsValidForConnection() {
		return NewInvalidStatusOutcome(tlResp, status)
	}

	expectedFP := tlResp.Payload.ServerCertFingerprint()
	if !cert.Fingerprint.Matches(expectedFP) {
		return NewFingerprintMismatchOutcome(tlResp, expectedFP, cert.Fingerprint.String())
	}

	tlHost := tlResp.Payload.AgentHost
	certFqdn := cert.FQDN()

	if !strings.EqualFold(tlHost, fqdn.String()) {
		return NewHostnameMismatchOutcome(tlResp, fqdn.String(), tlHost)
	}

	if certFqdn != nil && !strings.EqualFold(*certFqdn, tlHost) {
		return NewHostnameMismatchOutcome(tlResp, tlHost, *certFqdn)
	}

	outcome := NewVerifiedOutcome(tlResp, cert.Fingerprint)
	if status == models.TLStatusDeprecated {
		outcome.Warnings = append(outcome.Warnings, "agent status is DEPRECATED")
	}
	return outcome
}

// ClientVerifier verifies mTLS client certificates against the ANS transparency log.
// Use this when a server wants to verify that an mTLS client is a legitimate ANS agent.
type ClientVerifier struct {
	config *verifierConfig
}

// NewClientVerifier creates a new client verifier with the given options.
func NewClientVerifier(opts ...Option) *ClientVerifier {
	config := defaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return &ClientVerifier{config: config}
}

// Verify verifies an mTLS client certificate.
func (v *ClientVerifier) Verify(ctx context.Context, cert *CertIdentity) *VerificationOutcome {
	log := configLogger(v.config)

	// 0. A client cert must carry a subject identity (CN or DNS SAN).
	if cert.FQDN() == nil {
		log.InfoContext(ctx, "[client-verify] cert has no CN or DNS SAN")
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoCN})
	}

	// 1. Extract ANS name from URI SANs (ati://v1.x.x.host)
	atiName := cert.ATIName()
	if atiName == nil {
		log.InfoContext(ctx, "[client-verify] no ati:// URI SAN in cert")
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoURISAN})
	}

	// 2. Use ATI name host as the authoritative FQDN for badge lookup
	fqdn, err := models.NewFqdn(atiName.Host)
	if err != nil {
		return NewCertErrorOutcome(err)
	}

	// 3. Extract version
	version := atiName.Version
	log.InfoContext(ctx, "[client-verify] badge lookup",
		slog.String("fqdn", fqdn.String()),
		slog.String("version", version.String()),
		slog.String("atiName", atiName.String()))

	// 4. Check cache first (by FQDN + version)
	if v.config.cache != nil {
		if cached, ok := v.config.cache.GetByFqdnVersion(fqdn, version); ok {
			log.InfoContext(ctx, "[client-verify] cache hit", slog.String("fqdn", fqdn.String()))
			result := v.verifyWithTLResponse(cached.TLResponse, cert, fqdn, atiName)
			if rejection := v.applyDANE(ctx, fqdn, cert, result); rejection != nil {
				return rejection
			}
			return result
		}
	}

	// 5. Fetch TL response from DNS + TLog (matching version)
	tlResp, outcome := v.fetchTLResponse(ctx, fqdn, version)
	if outcome != nil {
		return outcome
	}

	// 6. Cache the TL response
	if v.config.cache != nil {
		v.config.cache.InsertForVersion(fqdn, version, tlResp)
	}

	// 7. Verify against TL response
	outcome = v.verifyWithTLResponse(tlResp, cert, fqdn, atiName)
	if rejection := v.applyDANE(ctx, fqdn, cert, outcome); rejection != nil {
		return rejection
	}
	return outcome
}

// applyDANE runs an optional DANE/TLSA check when the badge outcome succeeded
// and a DANE resolver is configured. It returns a rejection outcome if DANE
// affirmatively rejects; otherwise it enriches outcome in place and returns nil.
func (v *ClientVerifier) applyDANE(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, outcome *VerificationOutcome) *VerificationOutcome {
	if outcome.Type != OutcomeVerified {
		return nil
	}
	return verifyDANE(ctx, v.config, fqdn, cert, outcome)
}

// VerifyWithScitt verifies an mTLS client certificate using SCITT receipts and status tokens.
// If headers are empty or nil, delegates to the standard badge-based Verify().
// If SCITT verification encounters a fallback-eligible transport error, falls back to badge.
func (v *ClientVerifier) VerifyWithScitt(ctx context.Context, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	log := configLogger(v.config)

	// Empty headers → badge path
	if headers == nil || headers.IsEmpty() {
		log.InfoContext(ctx, "VerifyWithScitt: no SCITT headers, falling back to badge")
		return v.Verify(ctx, cert)
	}

	// Both required per spec
	if !headers.HasBoth() {
		log.WarnContext(ctx, "VerifyWithScitt: partial SCITT headers, rejecting",
			slog.Bool("has_receipt", len(headers.Receipt) > 0),
			slog.Bool("has_token", len(headers.StatusToken) > 0))
		return NewScittErrorOutcome(errors.New("both X-SCITT-Receipt and X-ANS-Status-Token headers are required"))
	}

	fqdnStr := cert.FQDN()
	if fqdnStr == nil {
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoCN})
	}
	fqdn, err := models.NewFqdn(*fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}

	// Parity with badge path: client cert must carry an ati:// URI SAN.
	if cert.ATIName() == nil {
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoURISAN})
	}

	return verifyWithHeaders(ctx, v.config, fqdn, cert, headers, log, roleIdentity,
		func() *VerificationOutcome { return v.Verify(ctx, cert) })
}

// fetchTLResponse fetches a TL response from DNS and TLog for a specific version.
func (v *ClientVerifier) fetchTLResponse(ctx context.Context, fqdn models.Fqdn, version models.Version) (*models.TLResponse, *VerificationOutcome) {
	log := configLogger(v.config)

	log.InfoContext(ctx, "[client-verify] DNS badge lookup",
		slog.String("fqdn", fqdn.String()),
		slog.String("version", version.String()))
	record, err := v.config.dnsResolver.FindBadgeForVersion(ctx, fqdn, version)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			log.WarnContext(ctx, "[client-verify] DNS badge not found", slog.String("fqdn", fqdn.String()))
			return nil, NewNotATIAgentOutcome(fqdn.String())
		}
		log.WarnContext(ctx, "[client-verify] DNS error",
			slog.String("fqdn", fqdn.String()), slog.String("error", err.Error()))
		outcome := NewDNSErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, &version, outcome)
	}
	if record == nil {
		log.WarnContext(ctx, "[client-verify] DNS badge record is nil", slog.String("fqdn", fqdn.String()))
		return nil, NewNotATIAgentOutcome(fqdn.String())
	}

	tlURL := rewriteTLHost(v.config, record.URL, log)
	log.InfoContext(ctx, "[client-verify] fetching TLog",
		slog.String("url", tlURL),
		slog.String("badgeSource", record.Source.String()))

	tlResp, err := v.config.tlogClient.FetchTLResponse(ctx, tlURL)
	if err != nil {
		log.WarnContext(ctx, "[client-verify] TLog fetch error",
			slog.String("url", tlURL), slog.String("error", err.Error()))
		outcome := NewTlogErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, &version, outcome)
	}

	log.InfoContext(ctx, "[client-verify] TLog response received",
		slog.String("agentHost", tlResp.Payload.AgentHost),
		slog.String("agentStatus", tlResp.Payload.AgentStatus),
		slog.String("agentName", tlResp.Payload.AgentName))

	return tlResp, nil
}

// verifyWithTLResponse verifies a client certificate against a TL response.
func (v *ClientVerifier) verifyWithTLResponse(tlResp *models.TLResponse, cert *CertIdentity, fqdn models.Fqdn, atiName *ATIName) *VerificationOutcome {
	log := configLogger(v.config)

	status := models.TLAgentStatus(tlResp.Payload.AgentStatus)
	if !status.IsValidForConnection() {
		log.Warn("[client-verify] agent status invalid for connection", "status", string(status))
		return NewInvalidStatusOutcome(tlResp, status)
	}

	expectedFP := tlResp.Payload.IdentityCertFingerprint()
	log.Info("[client-verify] fingerprint comparison",
		"certFingerprint", cert.Fingerprint.String(),
		"tlExpectedFingerprint", expectedFP)
	if !cert.Fingerprint.Matches(expectedFP) {
		log.Warn("[client-verify] fingerprint MISMATCH")
		return NewFingerprintMismatchOutcome(tlResp, expectedFP, cert.Fingerprint.String())
	}
	log.Info("[client-verify] fingerprint MATCHED")

	tlHost := tlResp.Payload.AgentHost
	if !strings.EqualFold(tlHost, fqdn.String()) {
		log.Warn("[client-verify] hostname mismatch", "tlHost", tlHost, "certFqdn", fqdn.String())
		return NewHostnameMismatchOutcome(tlResp, fqdn.String(), tlHost)
	}

	tlATIName := tlResp.Payload.AgentName
	if !strings.EqualFold(tlATIName, atiName.String()) {
		log.Warn("[client-verify] ATI name mismatch", "tlATIName", tlATIName, "certATIName", atiName.String())
		return NewATINameMismatchOutcome(tlResp, tlATIName, atiName.String())
	}

	outcome := NewVerifiedOutcome(tlResp, cert.Fingerprint)
	if status == models.TLStatusDeprecated {
		outcome.Warnings = append(outcome.Warnings, "agent status is DEPRECATED")
	}
	return outcome
}

// AnsVerifier is a high-level facade combining server and client verification.
type AnsVerifier struct {
	server *ServerVerifier
	client *ClientVerifier
}

// NewAnsVerifier creates a new ANS verifier with the given options.
// Both server and client verifiers share the same config (including cache).
func NewAnsVerifier(opts ...Option) *AnsVerifier {
	config := defaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return &AnsVerifier{
		server: &ServerVerifier{config: config},
		client: &ClientVerifier{config: config},
	}
}

// VerifyServer verifies a server certificate for the given FQDN string.
func (v *AnsVerifier) VerifyServer(ctx context.Context, fqdnStr string, cert *CertIdentity) *VerificationOutcome {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}
	return v.server.Verify(ctx, fqdn, cert)
}

// VerifyClient verifies an mTLS client certificate.
func (v *AnsVerifier) VerifyClient(ctx context.Context, cert *CertIdentity) *VerificationOutcome {
	return v.client.Verify(ctx, cert)
}

// VerifyServerWithScitt verifies a server certificate using SCITT headers.
func (v *AnsVerifier) VerifyServerWithScitt(ctx context.Context, fqdnStr string, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}
	return v.server.VerifyWithScitt(ctx, fqdn, cert, headers)
}

// VerifyClientWithScitt verifies an mTLS client certificate using SCITT headers.
func (v *AnsVerifier) VerifyClientWithScitt(ctx context.Context, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	return v.client.VerifyWithScitt(ctx, cert, headers)
}

// Prefetch fetches and caches a TL response for an FQDN string.
func (v *AnsVerifier) Prefetch(ctx context.Context, fqdnStr string) (*models.TLResponse, error) {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return nil, err
	}
	return v.server.Prefetch(ctx, fqdn)
}

// configLogger returns the configured logger or the default.
func configLogger(config *verifierConfig) *slog.Logger {
	if config.logger != nil {
		return config.logger
	}
	return slog.Default()
}

// verifyWithHeaders is the shared SCITT verification logic for both server and client verifiers.
// The role parameter selects which cert array of the status token to match against:
// roleServer restricts to ValidServerCerts; roleIdentity restricts to ValidIdentityCerts.
func verifyWithHeaders(
	ctx context.Context,
	config *verifierConfig,
	fqdn models.Fqdn,
	cert *CertIdentity,
	headers *scitt.Headers,
	log *slog.Logger,
	role certRole,
	badgeFallback func() *VerificationOutcome,
) *VerificationOutcome {
	keys := config.scittKeyLookup
	if keys == nil {
		log.WarnContext(ctx, "VerifyWithScitt: SCITT headers present but no key lookup configured",
			slog.String("fqdn", fqdn.String()))
		return NewScittErrorOutcome(errors.New("SCITT headers present but no key lookup configured; use WithScittKeyLookup option"))
	}

	log.InfoContext(ctx, "VerifyWithScitt: verifying receipt and status token",
		slog.String("fqdn", fqdn.String()))

	// Verify receipt
	receipt, err := scitt.VerifyReceipt(headers.Receipt, keys)
	if err != nil {
		var transportErr *scitt.TransportError
		if errors.As(err, &transportErr) && transportErr.ShouldFallbackToBadge() {
			log.WarnContext(ctx, "VerifyWithScitt: receipt verification transport error, falling back to badge",
				slog.String("fqdn", fqdn.String()),
				slog.String("error", err.Error()))
			return badgeFallback()
		}
		log.WarnContext(ctx, "VerifyWithScitt: receipt verification failed",
			slog.String("fqdn", fqdn.String()),
			slog.String("error", err.Error()))
		return NewScittErrorOutcome(err)
	}

	// Verify status token
	token, err := scitt.VerifyStatusToken(headers.StatusToken, keys, config.clockSkewTolerance)
	if err != nil {
		var transportErr *scitt.TransportError
		if errors.As(err, &transportErr) && transportErr.ShouldFallbackToBadge() {
			log.WarnContext(ctx, "VerifyWithScitt: token verification transport error, falling back to badge",
				slog.String("fqdn", fqdn.String()),
				slog.String("error", err.Error()))
			return badgeFallback()
		}
		log.WarnContext(ctx, "VerifyWithScitt: status token verification failed",
			slog.String("fqdn", fqdn.String()),
			slog.String("error", err.Error()))
		return NewScittErrorOutcome(err)
	}

	// Check agent status allows connections
	if !token.Payload.Status.IsValidForConnection() {
		return NewScittErrorOutcome(fmt.Errorf("agent status %s does not allow connections", token.Payload.Status))
	}

	// Match certificate fingerprint against the role-appropriate cert array (constant-time).
	fp := cert.Fingerprint.Bytes()
	var matched bool
	switch role {
	case roleServer:
		matched = scitt.MatchesServerCert(&token.Payload, fp)
	case roleIdentity:
		matched = scitt.MatchesIdentityCert(&token.Payload, fp)
	}
	if !matched {
		return NewScittErrorOutcome(errors.New("certificate fingerprint does not match any cert in status token"))
	}

	// Bind token's ATIName host to the requested FQDN.
	// ATIName is guaranteed non-empty by decodeStatusPayload validation.
	atiName, err := ParseATIName(token.Payload.ATIName)
	if err != nil {
		return NewScittErrorOutcome(fmt.Errorf("invalid ATIName in status token: %w", err))
	}
	if !strings.EqualFold(atiName.Host, fqdn.String()) {
		return NewScittErrorOutcome(fmt.Errorf("status token ATIName host %q does not match requested fqdn %q", atiName.Host, fqdn.String()))
	}

	log.InfoContext(ctx, "VerifyWithScitt: verification succeeded",
		slog.String("fqdn", fqdn.String()),
		slog.String("tier", "FullScitt"),
		slog.Uint64("tree_size", receipt.TreeSize),
		slog.Uint64("leaf_index", receipt.LeafIndex),
		slog.String("agent_status", string(token.Payload.Status)))

	outcome := &VerificationOutcome{
		Type:               OutcomeVerified,
		Tier:               TierFullScitt,
		MatchedFingerprint: &cert.Fingerprint,
	}
	if token.Payload.Status == scitt.StatusDeprecated {
		outcome.Warnings = append(outcome.Warnings, "agent status is DEPRECATED")
	}

	return outcome
}
