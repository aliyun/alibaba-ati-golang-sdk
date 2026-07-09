package ati

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// AgentClient is the primary ATI SDK client for secure agent-to-agent communication.
// It provides mTLS transport + DNS discovery + multi-level trust verification.
type AgentClient struct {
	httpClient     *http.Client
	tlsConfig      *tls.Config
	trustLevel     *TrustLevel
	identityCert   tls.Certificate
	caCertPool     *x509.CertPool
	certExpiry     time.Time
	dnsResolver    verify.DNSResolver
	daneResolver   verify.DANEResolver
	tlogClient     verify.TransparencyLogClient
	tlPublicKey    *ecdsa.PublicKey
	serverVerifier *verify.ServerVerifier
	verifyCache    sync.Map // host+fingerprint → *TrustOutcome
}

// AgentClientOption configures an AgentClient.
type AgentClientOption func(*agentClientConfig) error

type agentClientConfig struct {
	identityCertFile string
	privateKeyFile   string
	serverCertFile   string
	caBundleFile     string
	trustLevel       *TrustLevel
	targetVersion    string
	timeout          time.Duration
	dnsResolver      verify.DNSResolver
	daneResolver     verify.DANEResolver
	tlogClient       verify.TransparencyLogClient
	tlPublicKey      *ecdsa.PublicKey
}

// WithIdentityCert sets the client's identity certificate and private key for mTLS.
// The identity cert can be self-signed — the peer verifies it via TL fingerprint, not CA chain.
func WithIdentityCert(certFile, keyFile string) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.identityCertFile = certFile
		c.privateKeyFile = keyFile
		return nil
	}
}

// WithMTLSCerts loads PEM files for mTLS (backward-compatible).
// serverCert and caBundle are optional — pass empty strings to skip.
func WithMTLSCerts(identityCert, privateKey, serverCert, caBundle string) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.identityCertFile = identityCert
		c.privateKeyFile = privateKey
		c.serverCertFile = serverCert
		c.caBundleFile = caBundle
		return nil
	}
}

// WithTrustLevel sets the verification trust level.
// Supported levels for client: PKIOnly, BadgeRequired, DANEAndBadge.
// When not called, the client defaults to BadgeRequired.
func WithTrustLevel(level TrustLevel) AgentClientOption {
	return func(c *agentClientConfig) error {
		if !level.ValidForClient() {
			return fmt.Errorf("trust level %s is not supported for client (use PKIOnly, BadgeRequired, or DANEAndBadge)", level)
		}
		c.trustLevel = &level
		return nil
	}
}

// WithClientTimeout sets the HTTP client timeout.
func WithClientTimeout(d time.Duration) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.timeout = d
		return nil
	}
}

// WithDNSResolver sets a custom DNS resolver for testing.
func WithDNSResolver(r verify.DNSResolver) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.dnsResolver = r
		return nil
	}
}

// WithAgentDANEResolver sets a DANE resolver for Silver-level TLSA verification.
func WithAgentDANEResolver(r verify.DANEResolver) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.daneResolver = r
		return nil
	}
}

// WithTLogClient sets a custom transparency log client for Gold-level verification.
func WithTLogClient(t verify.TransparencyLogClient) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.tlogClient = t
		return nil
	}
}

// WithAliyunDiscovery uses the Aliyun DescribeAtiAgentRegisterInfoMarket API for
// agent discovery (_ati replacement), while badge lookups still use DNS TXT records.
func WithAliyunDiscovery(cfg verify.AliyunATIConfig) AgentClientOption {
	return func(c *agentClientConfig) error {
		resolver, err := verify.NewAliyunATIDiscovery(cfg)
		if err != nil {
			return fmt.Errorf("aliyun discovery: %w", err)
		}
		c.dnsResolver = resolver
		return nil
	}
}

// WithTLPublicKey sets a pre-configured CNNIC TL public key for Gold seal verification.
func WithTLPublicKey(key *ecdsa.PublicKey) AgentClientOption {
	return func(c *agentClientConfig) error {
		c.tlPublicKey = key
		return nil
	}
}

// WithTargetVersion sets the target agent version for discovery queries.
// Accepts semver expressions:
//   - Exact: "1.0.0" or "v1.0.0"
//   - Caret: "^1.0.0" (>=1.0.0, <2.0.0)
//   - Tilde: "~1.0.0" (>=1.0.0, <1.1.0)
//   - Range: ">=1.0.0"
//
// When empty, queries the latest version.
func WithTargetVersion(version string) AgentClientOption {
	return func(c *agentClientConfig) error {
		if version == "" {
			return nil
		}
		normalized, err := normalizeVersionExpr(version)
		if err != nil {
			return err
		}
		c.targetVersion = normalized
		return nil
	}
}

// normalizeVersionExpr validates and normalizes a semver range expression.
// Returns the API-compatible format (no "v" prefix): "1.0.0", "^1.0.0", "~1.0.0", ">=1.0.0".
func normalizeVersionExpr(expr string) (string, error) {
	prefix := ""
	semverPart := expr

	switch {
	case strings.HasPrefix(expr, ">="):
		prefix = ">="
		semverPart = expr[2:]
	case strings.HasPrefix(expr, "^"):
		prefix = "^"
		semverPart = expr[1:]
	case strings.HasPrefix(expr, "~"):
		prefix = "~"
		semverPart = expr[1:]
	}

	v, err := models.ParseVersion(semverPart)
	if err != nil {
		return "", fmt.Errorf("invalid version expression %q: %w", expr, err)
	}

	// API expects no "v" prefix: "1.0.0", "^1.0.0", etc.
	return fmt.Sprintf("%s%d.%d.%d", prefix, v.Major, v.Minor, v.Patch), nil
}

// NewAgentClient creates a new mTLS-based agent client.
func NewAgentClient(opts ...AgentClientOption) (*AgentClient, error) {
	cfg := &agentClientConfig{
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	// Client defaults to BadgeRequired when no trust level is specified.
	if cfg.trustLevel == nil {
		defaultLevel := BadgeRequired
		cfg.trustLevel = &defaultLevel
	}

	if cfg.identityCertFile == "" || cfg.privateKeyFile == "" {
		return nil, errors.New("identity certificate and private key are required: use WithIdentityCert()")
	}

	// Load identity certificate + private key (can be self-signed)
	identityCert, err := tls.LoadX509KeyPair(cfg.identityCertFile, cfg.privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%s 或 %s 不是有效的证书/密钥对: %w", cfg.identityCertFile, cfg.privateKeyFile, err)
	}

	if len(identityCert.Certificate) == 0 {
		return nil, fmt.Errorf("%s 不包含有效的 X.509 证书", cfg.identityCertFile)
	}
	x509Cert, err := x509.ParseCertificate(identityCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%s 不是有效的 X.509 证书: %w", cfg.identityCertFile, err)
	}

	hasATIName := false
	for _, uri := range x509Cert.URIs {
		if strings.HasPrefix(uri.String(), "ati://") {
			hasATIName = true
			break
		}
	}
	if !hasATIName {
		return nil, fmt.Errorf("identity certificate %s is missing an ati:// URI SAN — ATI Name not found", cfg.identityCertFile)
	}

	daysUntilExpiry := time.Until(x509Cert.NotAfter).Hours() / 24
	if daysUntilExpiry <= 30 {
		slog.Warn("Identity certificate expires soon", "days_remaining", int(daysUntilExpiry), "expires_at", x509Cert.NotAfter)
	}

	// Server cert verification: use custom CA bundle if provided, otherwise system CA.
	var caCertPool *x509.CertPool
	if cfg.caBundleFile != "" {
		caBundlePEM, readErr := os.ReadFile(cfg.caBundleFile)
		if readErr != nil {
			return nil, fmt.Errorf("无法读取 CA bundle %s: %w", cfg.caBundleFile, readErr)
		}
		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caBundlePEM) {
			return nil, fmt.Errorf("%s 不包含有效的 PEM 证书", cfg.caBundleFile)
		}
	}
	// caCertPool == nil → tls.Config.RootCAs uses system CA pool

	// Build TLS config: client presents identity cert, verifies server via public/custom CA
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{identityCert},
		RootCAs:          caCertPool,
		MinVersion:       tls.VersionTLS13,
		VerifyConnection: buildClientVerifyConnection(cfg, caCertPool),
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	resolver := cfg.dnsResolver
	if resolver == nil {
		resolver, err = defaultDiscoveryResolver()
		if err != nil {
			return nil, err
		}
	}

	// Set target version on Aliyun discovery resolver
	if cfg.targetVersion != "" {
		if aliyunResolver, ok := resolver.(*verify.AliyunATIDiscovery); ok {
			aliyunResolver.SetTargetVersion(cfg.targetVersion)
		}
	}

	tlogClient := cfg.tlogClient
	if tlogClient == nil {
		tlogClient = verify.NewHTTPTransparencyLogClient()
	}

	// Auto-create DANE resolver when trust level requires it
	daneResolver := cfg.daneResolver
	if daneResolver == nil && cfg.trustLevel != nil && *cfg.trustLevel >= DANEAndBadge {
		var daneOpts []verify.DANEResolverOption
		if dnsServer := globalDNSServer(); dnsServer != "" {
			daneOpts = append(daneOpts, verify.WithDANEServer(dnsServer))
		}
		daneResolver = verify.NewStandardDANEResolver(daneOpts...)
	}

	verifyOpts := []verify.Option{
		verify.WithDNSResolver(resolver),
		verify.WithTlogClient(tlogClient),
		verify.WithTrustedTLHost(verify.DefaultTrustedTLHost),
		verify.WithCacheConfig(verify.DefaultCacheConfig()),
	}
	// DANE is run by Do() using the correct server query (Verify on _443._tcp).
	// It is intentionally NOT wired into the ServerVerifier here to avoid a
	// second DANE pass.
	serverVerifier := verify.NewServerVerifier(verifyOpts...)

	return &AgentClient{
		httpClient: &http.Client{
			Timeout:   cfg.timeout,
			Transport: transport,
		},
		tlsConfig:      tlsConfig,
		trustLevel:     cfg.trustLevel, // nil means auto-detect
		identityCert:   identityCert,
		caCertPool:     caCertPool,
		certExpiry:     x509Cert.NotAfter,
		dnsResolver:    resolver,
		daneResolver:   daneResolver,
		tlogClient:     tlogClient,
		tlPublicKey:    cfg.tlPublicKey,
		serverVerifier: serverVerifier,
	}, nil
}

// CertStatus returns the remaining validity of the identity certificate.
type CertStatus struct {
	ExpiresAt     time.Time
	DaysRemaining int
	IsExpired     bool
}

// CertStatus returns the status of the loaded identity certificate.
func (c *AgentClient) CertStatus() CertStatus {
	days := int(time.Until(c.certExpiry).Hours() / 24)
	return CertStatus{
		ExpiresAt:     c.certExpiry,
		DaysRemaining: days,
		IsExpired:     time.Now().After(c.certExpiry),
	}
}

// Response wraps an HTTP response with verification information.
type Response struct {
	*http.Response
	VerificationOutcome *TrustOutcome
}

// TrustOutcome represents the result of trust-level verification.
type TrustOutcome struct {
	DNSDiscovered  bool        // _ati TXT record found
	CAChainValid   bool        // Peer cert signed by trusted CA
	SANMatches     bool        // URI SAN host matches connection target
	AgentID        string      // Agent ID from _ati record
	PeerATIName    string      // Peer's ATI name from cert URI SAN
	BadgeVerified  bool        // Badge verification passed
	DANEVerified   bool        // DANE/TLSA verification passed
	AchievedLevel  TrustLevel  // Highest achieved trust level
	RequestedLevel *TrustLevel // Requested level (nil = auto-detect)

	BadgeOutcome *verify.VerificationOutcome // Detailed badge verification result
	DANEDetails  *verify.DANEOutcome         // Detailed DANE verification result
}

// BronzeOutcome is a backward-compatible alias for TrustOutcome.
type BronzeOutcome = TrustOutcome

// IsVerified returns true if all PKI-level checks passed.
func (o *TrustOutcome) IsVerified() bool {
	return o.DNSDiscovered && o.CAChainValid && o.SANMatches
}

// Get performs a GET request with mTLS + Bronze verification.
func (c *AgentClient) Get(ctx context.Context, urlStr string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, urlStr, nil)
}

// Post performs a POST request with mTLS + Bronze verification.
func (c *AgentClient) Post(ctx context.Context, urlStr string, body any) (*Response, error) {
	return c.Do(ctx, http.MethodPost, urlStr, body)
}

// Put performs a PUT request with mTLS + Bronze verification.
func (c *AgentClient) Put(ctx context.Context, urlStr string, body any) (*Response, error) {
	return c.Do(ctx, http.MethodPut, urlStr, body)
}

// Delete performs a DELETE request with mTLS + Bronze verification.
func (c *AgentClient) Delete(ctx context.Context, urlStr string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, urlStr, nil)
}

// Do performs an HTTP request with mTLS + multi-level trust verification.
//
// When a trust level is specified (via WithTrustLevel), the request fails if
// the peer does not meet that level. When no level is specified (auto-detect),
// all levels are probed and the highest achieved level is reported in
// TrustOutcome.AchievedLevel.
//
// Verification results are cached per (host, cert fingerprint). Subsequent
// requests to the same server with the same certificate skip re-verification.
func (c *AgentClient) Do(ctx context.Context, method, urlStr string, body any) (*Response, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid URL: missing hostname: %s", urlStr)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("mTLS requires HTTPS, got scheme %q", parsedURL.Scheme)
	}

	explicit := c.trustLevel != nil
	outcome := &TrustOutcome{RequestedLevel: c.trustLevel}

	fqdn, fqdnErr := models.NewFqdn(host)
	if fqdnErr != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", host, fqdnErr)
	}

	// --- PKI: agent discovery ---
	// Runs before the request so that an explicit trust level blocks the
	// connection (no bytes sent to the server) when the agent is not discoverable.
	outcome.DNSDiscovered, outcome.AgentID = c.checkDNSDiscovery(ctx, fqdn)
	slog.Info("[verify] PKI: agent discovery", "fqdn", fqdn.String(), "found", outcome.DNSDiscovered, "agentID", outcome.AgentID)
	if !outcome.DNSDiscovered && explicit {
		return nil, fmt.Errorf("PKI verification failed: agent not found for %s", host)
	}

	// --- Execute request (mTLS handshake happens here) ---
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", marshalErr)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Check if we already verified this server (same host + same cert)
	var cacheKey string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		fp := verify.CertFingerprintFromDER(resp.TLS.PeerCertificates[0].Raw)
		cacheKey = host + "|" + fp.ToHex()
		if cached, ok := c.verifyCache.Load(cacheKey); ok {
			slog.Info("[verify] using cached verification result", "host", host)
			return &Response{
				Response:            resp,
				VerificationOutcome: cached.(*TrustOutcome),
			}, nil
		}
	}

	// --- PKI: CA chain + SAN match ---
	var certIdentity *verify.CertIdentity
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		peerCert := resp.TLS.PeerCertificates[0]
		outcome.CAChainValid = true

		for _, dnsName := range peerCert.DNSNames {
			if strings.EqualFold(dnsName, host) {
				outcome.SANMatches = true
				break
			}
		}

		for _, uri := range peerCert.URIs {
			if strings.HasPrefix(uri.String(), "ati://") {
				outcome.PeerATIName = uri.String()
				break
			}
		}

		certIdentity = verify.CertIdentityFromX509(peerCert)
	}

	slog.Info("[verify] PKI: TLS handshake", "caChainValid", outcome.CAChainValid, "sanMatches", outcome.SANMatches)

	if outcome.DNSDiscovered && outcome.CAChainValid && outcome.SANMatches {
		outcome.AchievedLevel = PKIOnly
	}

	// --- Badge verification ---
	shouldBadge := !explicit || *c.trustLevel >= BadgeRequired
	if shouldBadge && certIdentity != nil {
		slog.Info("[verify] Badge: starting verification", "fqdn", fqdn.String())
		badgeOutcome := c.serverVerifier.Verify(ctx, fqdn, certIdentity)
		outcome.BadgeOutcome = badgeOutcome
		slog.Info("[verify] Badge: result", "success", badgeOutcome.IsSuccess(), "outcome", badgeOutcome.ToError())
		if badgeOutcome.IsSuccess() {
			outcome.BadgeVerified = true
			outcome.AchievedLevel = BadgeRequired
		} else if explicit && *c.trustLevel >= BadgeRequired {
			resp.Body.Close()
			return nil, fmt.Errorf("badge verification failed for %s: %v", host, badgeOutcome.ToError())
		}
	}

	// --- DANE/Full verification ---
	shouldDANE := !explicit || *c.trustLevel >= DANEAndBadge
	if shouldDANE && outcome.BadgeVerified && c.daneResolver != nil && certIdentity != nil {
		slog.Info("[verify] DANE: starting TLSA verification", "fqdn", fqdn.String(), "port", 443)
		daneVerifier := verify.NewDANEVerifier(c.daneResolver)
		daneOutcome := daneVerifier.Verify(ctx, fqdn, 443, certIdentity)
		outcome.DANEDetails = daneOutcome
		slog.Info("[verify] DANE: result", "type", daneOutcome.Type.String(), "pass", daneOutcome.IsPass(), "error", daneOutcome.Error)
		if daneOutcome.IsPass() {
			outcome.DANEVerified = true
			outcome.AchievedLevel = DANEAndBadge
		} else if daneOutcome.IsReject() && explicit {
			resp.Body.Close()
			return nil, fmt.Errorf("DANE verification failed for %s: %v", host, daneOutcome.Error)
		}
	}

	// In explicit mode, verify we reached the requested level.
	if explicit && outcome.AchievedLevel < *c.trustLevel {
		resp.Body.Close()
		return nil, fmt.Errorf("requested trust level %s not achieved (got %s)", c.trustLevel, outcome.AchievedLevel)
	}

	// Cache successful verification
	if cacheKey != "" {
		c.verifyCache.Store(cacheKey, outcome)
	}

	return &Response{
		Response:            resp,
		VerificationOutcome: outcome,
	}, nil
}

// Prefetch verifies DNS discovery for a host without making a request.
func (c *AgentClient) Prefetch(ctx context.Context, host string) error {
	fqdn, err := models.NewFqdn(host)
	if err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}
	discovered, _ := c.checkDNSDiscovery(ctx, fqdn)
	if !discovered {
		return fmt.Errorf("no _ati TXT record found for %s", host)
	}
	return nil
}

// checkDNSDiscovery queries agent discovery (via DNS or Aliyun API).
func (c *AgentClient) checkDNSDiscovery(ctx context.Context, fqdn models.Fqdn) (found bool, agentID string) {
	result, err := c.dnsResolver.LookupATIDiscovery(ctx, fqdn)
	if err != nil {
		slog.Warn("agent discovery failed", "fqdn", fqdn.String(), "error", err.Error())
		return false, ""
	}
	if !result.Found {
		return false, ""
	}
	if len(result.Records) > 0 {
		return true, result.Records[0].ID
	}
	return true, ""
}

// buildClientVerifyConnection creates a VerifyConnection callback for the client TLS config.
// It performs peer certificate validity checks during the handshake.
func buildClientVerifyConnection(cfg *agentClientConfig, _ *x509.CertPool) func(tls.ConnectionState) error {
	_ = cfg
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return nil
		}
		peerCert := cs.PeerCertificates[0]

		// Peer cert validity check + expiry warning (§8.1)
		validityCheck := verify.CheckCertValidity(peerCert, time.Now())
		if !validityCheck.Valid {
			return fmt.Errorf("peer certificate invalid: %s", validityCheck.Warning)
		}
		if validityCheck.Warning != "" {
			slog.Warn("peer certificate expiry warning",
				"host", cs.ServerName,
				"warning", validityCheck.Warning)
		}

		return nil
	}
}
