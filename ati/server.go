package ati

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// ServerOption configures the server-side TLS configuration.
type ServerOption func(*serverConfig) error

type serverConfig struct {
	serverCertFile string
	privateKeyFile string
	caBundleFile   string
	trustLevel     *TrustLevel
	dnsResolver    verify.DNSResolver
	daneResolver   verify.DANEResolver
	tlogClient     verify.TransparencyLogClient
	clientVerifier *verify.ClientVerifier
	peerLevels     *sync.Map // cert fingerprint → TrustLevel (for auto-detect)
}

// WithServerCert sets the server certificate and private key files.
func WithServerCert(serverCert, privateKey string) ServerOption {
	return func(c *serverConfig) error {
		c.serverCertFile = serverCert
		c.privateKeyFile = privateKey
		return nil
	}
}

// WithClientCA sets the CA bundle for verifying client certificates.
func WithClientCA(caBundle string) ServerOption {
	return func(c *serverConfig) error {
		c.caBundleFile = caBundle
		return nil
	}
}

// WithClientVerifier sets the trust level for client verification.
// Supported levels: PKIOnly, BadgeRequired, DANEAndBadge.
//
// When not called, the server performs NO client verification — it does not
// request a client certificate and accepts the connection as a plain TLS
// connection. (Exception: providing a private root cert via WithClientCA
// implies PKIOnly verification.)
func WithClientVerifier(level TrustLevel) ServerOption {
	return func(c *serverConfig) error {
		if !level.ValidForServer() {
			return fmt.Errorf("trust level %s is not supported for server (use PKIOnly, BadgeRequired, or DANEAndBadge)", level)
		}
		c.trustLevel = &level
		return nil
	}
}

// WithPeerLevelStore injects a shared sync.Map for storing per-peer achieved trust
// levels. The map is keyed by cert fingerprint (hex) and values are TrustLevel.
// Use this with PeerTrustLevel() to query what level a peer actually achieved.
func WithPeerLevelStore(store *sync.Map) ServerOption {
	return func(c *serverConfig) error {
		c.peerLevels = store
		return nil
	}
}

// WithServerDANEResolver sets a DANE resolver for TrustFull-level client verification.
func WithServerDANEResolver(r verify.DANEResolver) ServerOption {
	return func(c *serverConfig) error {
		c.daneResolver = r
		return nil
	}
}

// WithServerAliyunDiscovery uses the Aliyun DescribeAtiAgentRegisterInfoMarket API for
// client discovery (_ati replacement), while badge lookups still use DNS TXT records.
func WithServerAliyunDiscovery(cfg verify.AliyunATIConfig) ServerOption {
	return func(c *serverConfig) error {
		resolver, err := verify.NewAliyunATIDiscovery(cfg)
		if err != nil {
			return fmt.Errorf("aliyun discovery: %w", err)
		}
		c.dnsResolver = resolver
		return nil
	}
}

// NewServerTLSConfig creates a TLS configuration for an agent server.
//
// The verification behavior depends on WithClientVerifier / WithClientCA:
//   - Neither set: no client verification. The server does not request a client
//     certificate and accepts the connection as a plain TLS connection.
//   - WithClientVerifier(level) set: mutual TLS with a VerifyConnection callback
//     enforcing the given trust level. Client certificates can be self-signed —
//     trust is established through TL fingerprint verification.
//   - WithClientCA set: the CA chain is also validated, and PKIOnly verification
//     is implied even without WithClientVerifier.
func NewServerTLSConfig(opts ...ServerOption) (*tls.Config, error) {
	// trustLevel is left nil by default. When WithClientVerifier is not called,
	// the server performs no client verification at all — behaving like a plain
	// TLS connection (no client certificate is requested).
	cfg := &serverConfig{
		peerLevels: &sync.Map{},
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.serverCertFile == "" || cfg.privateKeyFile == "" {
		return nil, errors.New("server certificate and private key are required: use WithServerCert()")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.serverCertFile, cfg.privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%s 或 %s 不是有效的证书/密钥对: %w", cfg.serverCertFile, cfg.privateKeyFile, err)
	}

	// Providing a private root cert (CA bundle) is an explicit request to verify
	// the client, so it implies at least PKIOnly even when no trust level was set.
	if cfg.trustLevel == nil && cfg.caBundleFile != "" {
		lvl := PKIOnly
		cfg.trustLevel = &lvl
	}

	// Determine the TLS client-auth mode from the configured trust level:
	//   - no trust level        → NoClientCert (plain connection, no mTLS)
	//   - CA bundle provided     → RequireAndVerifyClientCert (CA chain validated)
	//   - trust level, no bundle → RequireAnyClientCert (trust via Badge/TLog)
	var clientCAs *x509.CertPool
	var clientAuth tls.ClientAuthType
	switch {
	case cfg.trustLevel == nil:
		clientAuth = tls.NoClientCert
	case cfg.caBundleFile != "":
		caBundlePEM, readErr := os.ReadFile(cfg.caBundleFile)
		if readErr != nil {
			return nil, fmt.Errorf("无法读取 CA bundle %s: %w", cfg.caBundleFile, readErr)
		}
		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(caBundlePEM) {
			return nil, fmt.Errorf("%s 不包含有效的 PEM 证书", cfg.caBundleFile)
		}
		clientAuth = tls.RequireAndVerifyClientCert
	default:
		clientAuth = tls.RequireAnyClientCert
	}

	// Auto-create DANE resolver when trust level requires it
	if cfg.daneResolver == nil && cfg.trustLevel != nil && *cfg.trustLevel >= DANEAndBadge {
		var daneOpts []verify.DANEResolverOption
		if dnsServer := globalDNSServer(); dnsServer != "" {
			daneOpts = append(daneOpts, verify.WithDANEServer(dnsServer))
		}
		cfg.daneResolver = verify.NewStandardDANEResolver(daneOpts...)
	}

	// Default discovery resolver. Only required when badge/DANE verification is
	// requested — a PKIOnly server never performs discovery.
	if cfg.dnsResolver == nil && cfg.trustLevel != nil && *cfg.trustLevel >= BadgeRequired {
		resolver, err := defaultDiscoveryResolver()
		if err != nil {
			return nil, err
		}
		cfg.dnsResolver = resolver
	}

	// Build ClientVerifier for TL-based fingerprint verification
	var verifyOpts []verify.Option
	if cfg.dnsResolver != nil {
		verifyOpts = append(verifyOpts, verify.WithDNSResolver(cfg.dnsResolver))
	}
	if cfg.tlogClient != nil {
		verifyOpts = append(verifyOpts, verify.WithTlogClient(cfg.tlogClient))
	}
	// DANE is run by buildVerifyConnection using the correct per-role query
	// (VerifyIdentity for client identity certs). It is intentionally NOT wired
	// into the ClientVerifier here to avoid a second, wrong-query DANE pass.
	verifyOpts = append(verifyOpts, verify.WithTrustedTLHost(verify.DefaultTrustedTLHost))
	cfg.clientVerifier = verify.NewClientVerifier(verifyOpts...)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS13,
	}

	// Only enforce trust verification when a level is configured. With no trust
	// level the connection is accepted as-is (plain TLS, nothing verified).
	if cfg.trustLevel != nil {
		tlsConfig.VerifyConnection = buildVerifyConnection(cfg)
	}

	return tlsConfig, nil
}

// buildVerifyConnection creates a VerifyConnection callback that enforces
// the configured trust level during the TLS handshake.
func buildVerifyConnection(cfg *serverConfig) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no client certificate provided")
		}

		peerCert := cs.PeerCertificates[0]

		// PKI (CA chain) validation is handled by Go's TLS library before this callback.
		// If we reach here, it means:
		// - With --ca-bundle: CA chain validation PASSED (cert signed by trusted CA)
		// - Without --ca-bundle: any client cert accepted (trust via Badge/TLog)
		caMode := "disabled (any cert accepted)"
		if cfg.caBundleFile != "" {
			caMode = "enabled (CA chain validated)"
		}
		slog.Info("[server-verify] PKI: client cert received",
			"subject", peerCert.Subject.CommonName,
			"issuer", peerCert.Issuer.CommonName,
			"notAfter", peerCert.NotAfter.Format("2006-01-02"),
			"caChainVerification", caMode)

		validityCheck := verify.CheckCertValidity(peerCert, time.Now())
		if !validityCheck.Valid {
			slog.Error("[server-verify] cert validity check FAILED", "reason", validityCheck.Warning)
			return fmt.Errorf("peer certificate invalid: %s", validityCheck.Warning)
		}
		slog.Info("[server-verify] cert validity check OK", "remainingPercent", fmt.Sprintf("%.0f%%", validityCheck.RemainingPercent*100))

		if validityCheck.Warning != "" {
			slog.Warn("[server-verify] cert expiry warning", "warning", validityCheck.Warning)
		}

		// TrustNone: only cert validity, already checked above.
		if cfg.trustLevel != nil && *cfg.trustLevel == PKIOnly {
			slog.Info("[server-verify] trust level: PKI_ONLY — accepting client")
			return nil
		}

		certIdentity := verify.CertIdentityFromX509(peerCert)
		achieved := PKIOnly
		explicit := cfg.trustLevel != nil

		fqdnVal := "<none>"
		if f := certIdentity.FQDN(); f != nil {
			fqdnVal = *f
		}
		atiNameVal := "<none>"
		if a := certIdentity.ATIName(); a != nil {
			atiNameVal = a.String()
		}
		slog.Info("[server-verify] client identity",
			"fingerprint", certIdentity.Fingerprint.ToHex(),
			"spkiFingerprint", certIdentity.SPKIFingerprint.ToHex(),
			"fqdn", fqdnVal,
			"atiName", atiNameVal)

		// Badge verification
		if !explicit || *cfg.trustLevel >= BadgeRequired {
			slog.Info("[server-verify] Badge: starting verification")
			outcome := cfg.clientVerifier.Verify(context.Background(), certIdentity)
			if outcome.IsSuccess() {
				achieved = BadgeRequired
				slog.Info("[server-verify] Badge: PASSED")
			} else {
				slog.Warn("[server-verify] Badge: FAILED", "error", outcome.ToError())
				if explicit {
					return fmt.Errorf("badge verification failed: %v", outcome.ToError())
				}
			}
		}

		// DANE verification (requires badge to have passed)
		if achieved >= BadgeRequired && (!explicit || *cfg.trustLevel >= DANEAndBadge) {
			if cfg.daneResolver != nil {
				// Use ATI name host for DANE lookup (same as badge)
				atiNameObj := certIdentity.ATIName()
				if atiNameObj != nil {
					fqdn, err := models.NewFqdn(atiNameObj.Host)
					if err == nil {
						slog.Info("[server-verify] DANE: starting identity TLSA verification",
							"fqdn", atiNameObj.Host,
							"queryName", "_ati-identity._tls."+atiNameObj.Host,
							"certFingerprint", certIdentity.Fingerprint.ToHex(),
							"spkiFingerprint", certIdentity.SPKIFingerprint.ToHex())
						daneVerifier := verify.NewDANEVerifier(cfg.daneResolver)
						daneOutcome := daneVerifier.VerifyIdentity(context.Background(), fqdn, certIdentity)
						slog.Info("[server-verify] DANE: result",
							"type", daneOutcome.Type.String(),
							"pass", daneOutcome.IsPass(),
							"error", daneOutcome.Error)
						if daneOutcome.IsPass() {
							achieved = DANEAndBadge
							slog.Info("[server-verify] DANE: PASSED")
						} else if daneOutcome.IsReject() {
							slog.Warn("[server-verify] DANE: REJECTED", "error", daneOutcome.Error)
							if explicit {
								return fmt.Errorf("DANE verification failed: %v", daneOutcome.Error)
							}
						}
					}
				} else {
					slog.Warn("[server-verify] DANE: skipped — no ati:// URI SAN in client cert")
				}
			}
		}

		// Store achieved level for application-layer queries.
		fp := certIdentity.Fingerprint.ToHex()
		if fp != "" {
			cfg.peerLevels.Store(fp, achieved)
		}

		slog.Info("[server-verify] final result", "achievedLevel", achieved.String(), "requestedLevel", fmt.Sprintf("%v", cfg.trustLevel))

		// In explicit mode, verify we reached the requested level.
		if explicit && achieved < *cfg.trustLevel {
			return fmt.Errorf("requested trust level %s not achieved (got %s)", cfg.trustLevel, achieved)
		}

		return nil
	}
}

// PeerTrustLevel returns the achieved trust level for a TLS peer.
// In auto-detect mode (no explicit trust level configured), this reports the
// highest level the peer actually supports. Returns nil if the peer has not
// been verified or is not found.
func PeerTrustLevel(state *tls.ConnectionState, peerLevels *sync.Map) *TrustLevel {
	if state == nil || len(state.PeerCertificates) == 0 || peerLevels == nil {
		return nil
	}
	fp := verify.CertIdentityFromX509(state.PeerCertificates[0]).Fingerprint.ToHex()
	if v, ok := peerLevels.Load(fp); ok {
		level := v.(TrustLevel)
		return &level
	}
	return nil
}

// ATIName represents a parsed ATI name from a certificate URI SAN.
type ATIName struct {
	Host    string
	Version string
	Raw     string
}

// PeerATIName extracts the peer's ATI identity from a TLS connection state.
func PeerATIName(state *tls.ConnectionState) (*ATIName, error) {
	if state == nil {
		return nil, errors.New("no TLS connection state")
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificates")
	}

	peerCert := state.PeerCertificates[0]
	for _, uri := range peerCert.URIs {
		uriStr := uri.String()
		if strings.HasPrefix(uriStr, "ati://") {
			parsed, err := verify.ParseATIName(uriStr)
			if err != nil {
				continue
			}
			return &ATIName{
				Host:    parsed.Host,
				Version: parsed.Version.String(),
				Raw:     uriStr,
			}, nil
		}
	}

	return nil, errors.New("no ati:// URI SAN found in peer certificate")
}
