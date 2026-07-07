// Package client implements the ATI demo web UI and Agent A orchestrator. It
// serves the embedded frontend, drives the live mTLS verification stream against
// the proxy, and runs the DashScope-powered A<->B orchestration over the
// mutually-authenticated tunnel.
package client

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/models"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"
)

//go:embed static
var staticFS embed.FS

// Config holds the demo client's runtime configuration.
type Config struct {
	ListenAddr   string
	Cert         string
	Key          string
	ClientHost   string
	Cert2        string
	Key2         string
	ClientHost2  string
	ProxyPort    string
	ProxyAPIAddr string
	DashKey      string
	DashModel    string
}

// Run starts the demo client web server and blocks until it exits.
func Run(cfg Config) error {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":7080"
	}
	if cfg.ClientHost == "" {
		cfg.ClientHost = "www.ats-client.asia"
	}
	if cfg.ClientHost2 == "" {
		cfg.ClientHost2 = "ats-client.asia"
	}
	if cfg.ProxyPort == "" {
		cfg.ProxyPort = "7443"
	}
	if cfg.ProxyAPIAddr == "" {
		cfg.ProxyAPIAddr = "http://localhost:7444"
	}
	if cfg.DashModel == "" {
		cfg.DashModel = "qwen-plus"
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return fmt.Errorf("client: cert and key are required")
	}

	identities := []clientIdentity{
		{Host: cfg.ClientHost, CertFile: cfg.Cert, KeyFile: cfg.Key},
	}
	if cfg.Cert2 != "" && cfg.Key2 != "" {
		identities = append(identities, clientIdentity{Host: cfg.ClientHost2, CertFile: cfg.Cert2, KeyFile: cfg.Key2})
	}

	app := &App{
		identities:   identities,
		proxyPort:    cfg.ProxyPort,
		proxyAPIAddr: strings.TrimRight(cfg.ProxyAPIAddr, "/"),
		debugLog:     newDebugLogCollector(),
		dashKey:      cfg.DashKey,
		dashModel:    cfg.DashModel,
		llmHTTP:      &http.Client{Timeout: 60 * time.Second},
	}

	slog.SetDefault(slog.New(app.debugLog))
	if cfg.DashKey == "" {
		slog.Warn("[client] DASHSCOPE_API_KEY not set — agentA orchestration will be degraded")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/client-identities", app.handleClientIdentities)
	mux.HandleFunc("GET /api/connect/stream", app.handleConnectStream)
	mux.HandleFunc("POST /api/chat", app.handleChat)
	mux.HandleFunc("GET /api/chat/stream", app.handleChatStream)
	mux.HandleFunc("POST /api/disconnect", app.handleDisconnect)
	mux.HandleFunc("GET /api/proxy-status", app.handleProxyStatus)
	mux.HandleFunc("PUT /api/server-policy", app.handleServerPolicy)
	mux.HandleFunc("GET /api/debug/logs", app.handleDebugLogs)
	mux.HandleFunc("POST /api/debug/toggle", app.handleDebugToggle)
	mux.HandleFunc("POST /api/debug/clear", app.handleDebugClear)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		data, err := staticFS.ReadFile("static" + path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(path, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		case strings.HasSuffix(path, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case strings.HasSuffix(path, ".js"):
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		w.Write(data)
	})

	log.Printf("ati-demo-client on %s", cfg.ListenAddr)
	return http.ListenAndServe(cfg.ListenAddr, mux)
}

// clientIdentity holds a client agent's hostname and associated certificate files.
type clientIdentity struct {
	Host     string `json:"host"`
	CertFile string `json:"-"`
	KeyFile  string `json:"-"`
}

// App holds the demo client application state.
type App struct {
	identities   []clientIdentity
	proxyPort    string
	proxyAPIAddr string
	debugLog     *DebugLogCollector
	dashKey      string
	dashModel    string
	llmHTTP      *http.Client

	mu             sync.Mutex
	client         *ati.AgentClient
	connected      bool
	agentHost      string
	conversationID string
}

// --- SSE Step Event ---

type StepEvent struct {
	Direction  string `json:"direction"`
	Step       string `json:"step"`
	Status     string `json:"status"`
	Title      string `json:"title"`
	SdkApi     string `json:"sdkApi,omitempty"`
	DurationMs *int64 `json:"durationMs"`
	Details    any    `json:"details,omitempty"`
	Error      any    `json:"error,omitempty"`
}

type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (s *sseWriter) send(ev StepEvent) {
	data, _ := json.Marshal(ev)
	fmt.Fprintf(s.w, "data: %s\n\n", data)
	s.flusher.Flush()
}

func durationMs(d time.Duration) *int64 {
	ms := d.Milliseconds()
	return &ms
}

// --- Connect Stream Handler ---

func (a *App) handleConnectStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sse := &sseWriter{w: w, flusher: flusher}

	agentHost := r.URL.Query().Get("agentHost")
	policy := r.URL.Query().Get("policy")
	clientHost := r.URL.Query().Get("clientHost")
	serverPolicy := r.URL.Query().Get("serverPolicy")
	serverVersion := r.URL.Query().Get("serverVersion")

	if agentHost == "" {
		agentHost = "ats-server.asia"
	}
	clientLevel := parseTrustLevel(policy)

	ctx := r.Context()

	// --- Step A1: Agent Discovery ---
	a1Start := time.Now()
	sse.send(StepEvent{Direction: "A", Step: "A1", Status: "running", Title: "Agent发现"})

	sse.send(StepEvent{Direction: "A", Step: "A1b", Status: "running",
		Title:  "调用阿里云 OpenAPI 查询agent注册信息",
		SdkApi: "alidns.aliyuncs.com :: DescribeAtiAgentRegisterInfoMarket",
	})

	ak := os.Getenv("ATI_AK")
	sk := os.Getenv("ATI_SK")
	var discoveryResult *verify.MarketplaceAgentInfo
	var discoveryErr error

	if ak != "" && sk != "" {
		disc, err := verify.NewAliyunATIDiscovery(verify.AliyunATIConfig{
			AccessKeyID:     ak,
			AccessKeySecret: sk,
		})
		if err == nil {
			if serverVersion != "" {
				disc.SetTargetVersion(serverVersion)
			}
			fqdn, fqdnErr := models.NewFqdn(agentHost)
			if fqdnErr != nil {
				discoveryErr = fmt.Errorf("invalid agentHost: %w", fqdnErr)
			} else {
				result, lookupErr := disc.LookupATIDiscovery(ctx, fqdn)
				if lookupErr != nil {
					discoveryErr = lookupErr
				} else if !result.Found || len(result.Records) == 0 {
					versionHint := "latest"
					if serverVersion != "" {
						versionHint = serverVersion
					}
					discoveryErr = fmt.Errorf("agent not found: %s (version: %s)", agentHost, versionHint)
				} else {
					// Lookup succeeded — also fetch full agent info for display
					discoveryResult, _ = disc.DescribeAgent(ctx, agentHost, disc.GetTargetVersion())
				}
			}
		} else {
			discoveryErr = err
		}
	} else {
		discoveryErr = fmt.Errorf("ATI_AK/ATI_SK not set")
	}

	if discoveryErr != nil {
		a1Dur := durationMs(time.Since(a1Start))
		slog.Error("[discovery] agent discovery failed",
			"agentHost", agentHost,
			"serverVersion", serverVersion,
			"akSet", ak != "",
			"error", discoveryErr)
		errDetail := map[string]string{
			"parentStep":    "A1",
			"agentHost":     agentHost,
			"serverVersion": serverVersion,
			"akConfigured":  fmt.Sprintf("%v", ak != ""),
			"endpoint":      "alidns.aliyuncs.com",
			"error":         discoveryErr.Error(),
		}
		sse.send(StepEvent{Direction: "A", Step: "A1b", Status: "failed",
			Title: "调用阿里云 OpenAPI 查询agent注册信息", DurationMs: a1Dur,
			Details: errDetail,
			Error:   map[string]string{"type": "DiscoveryError", "message": discoveryErr.Error()},
		})
		sse.send(StepEvent{Direction: "A", Step: "A1", Status: "failed",
			Title: "Agent发现", DurationMs: a1Dur,
			Details: map[string]string{"agentHost": agentHost, "error": discoveryErr.Error()},
			Error:   map[string]string{"type": "DiscoveryError", "message": discoveryErr.Error()},
		})
		return
	}

	a1bDur := durationMs(time.Since(a1Start))
	var agentID string
	if discoveryResult != nil {
		agentID = discoveryResult.AgentID
	}
	sse.send(StepEvent{Direction: "A", Step: "A1b", Status: "success",
		Title: "调用阿里云 OpenAPI 查询agent注册信息", DurationMs: a1bDur,
		SdkApi:  "alidns.aliyuncs.com :: DescribeAgentRegisterInfoMarket",
		Details: map[string]string{"parentStep": "A1", "agentId": agentID},
	})

	a1Details := map[string]any{}
	if discoveryResult != nil {
		a1Details["agentId"] = discoveryResult.AgentID
		a1Details["agentDisplayName"] = discoveryResult.AgentDisplayName
		a1Details["agentHost"] = discoveryResult.AgentHost
		a1Details["agentVersion"] = discoveryResult.AgentVersion
		a1Details["status"] = discoveryResult.Status
		a1Details["trustLevel"] = discoveryResult.TrustLevel
		if discoveryResult.AgentDescription != "" {
			a1Details["agentDescription"] = discoveryResult.AgentDescription
		}
		if len(discoveryResult.Categories) > 0 {
			a1Details["categories"] = discoveryResult.Categories
		}
		if len(discoveryResult.Endpoints) > 0 {
			eps := make([]map[string]any, 0, len(discoveryResult.Endpoints))
			for _, ep := range discoveryResult.Endpoints {
				eps = append(eps, map[string]any{
					"protocol":    ep.Protocol,
					"agentUrl":    ep.AgentURL,
					"metadataUrl": ep.MetadataURL,
					"transports":  ep.Transports,
				})
			}
			a1Details["endpoints"] = eps
		}
	}
	sse.send(StepEvent{Direction: "A", Step: "A1", Status: "success",
		Title: "Agent发现", DurationMs: a1bDur,
		SdkApi:  "AtiDiscoveryClient.discover(agentHost, serverVersion)",
		Details: a1Details,
	})

	// --- Step A2: 凭证认证 (starts here, sub-steps emitted after A3 with real data) ---
	var a2Start time.Time
	if clientLevel >= ati.BadgeRequired {
		a2Start = time.Now()
		sse.send(StepEvent{Direction: "A", Step: "A2", Status: "running",
			Title: "凭证认证", SdkApi: "AtiVerifiedClient.connectAsync()",
		})
	}

	// --- Step A3: PKI认证 (mTLS handshake) ---
	a3Start := time.Now()
	sse.send(StepEvent{Direction: "A", Step: "A3", Status: "running",
		Title: "PKI认证", SdkApi: "mTLS Handshake",
	})

	// A3a: ClientHello
	sse.send(StepEvent{Direction: "A", Step: "A3a", Status: "running",
		Title: "发起TLS连接请求",
	})
	sse.send(StepEvent{Direction: "A", Step: "A3a", Status: "success",
		Title: "发起TLS连接请求", DurationMs: durationMs(time.Since(a3Start)),
		Details: map[string]string{"parentStep": "A3", "cipher": "TLS_AES_256_GCM_SHA384", "tlsVersion": "TLS 1.3"},
	})

	// A3b: ServerHello + server cert
	sse.send(StepEvent{Direction: "A", Step: "A3b", Status: "running",
		Title: "收到Server公有证书，Server请求验证Client身份",
	})
	sse.send(StepEvent{Direction: "A", Step: "A3b", Status: "success",
		Title: "收到Server公有证书，Server请求验证Client身份", DurationMs: durationMs(time.Since(a3Start)),
		Details: map[string]string{"parentStep": "A3"},
	})

	// A3c: Send identity cert
	sse.send(StepEvent{Direction: "A", Step: "A3c", Status: "running",
		Title: "发送Client身份证书",
	})
	sse.send(StepEvent{Direction: "A", Step: "A3c", Status: "success",
		Title: "发送Client身份证书", DurationMs: durationMs(time.Since(a3Start)),
		Details: map[string]string{"parentStep": "A3"},
	})

	// --- B1: PKI认证 (server side, emitted in parallel with A3) ---
	sse.send(StepEvent{Direction: "B", Step: "B1", Status: "running", Title: "PKI认证"})
	sse.send(StepEvent{Direction: "B", Step: "B1-1", Status: "running",
		Title: "收到连接请求，发送Server公有证书并请求Client身份",
	})
	sse.send(StepEvent{Direction: "B", Step: "B1-1", Status: "success",
		Title:   "收到连接请求，发送Server公有证书并请求Client身份",
		Details: map[string]string{"parentStep": "B1"},
	})
	sse.send(StepEvent{Direction: "B", Step: "B1-2", Status: "running",
		Title: "收到Client身份证书",
	})
	sse.send(StepEvent{Direction: "B", Step: "B1-2", Status: "success",
		Title:   "收到Client身份证书",
		Details: map[string]string{"parentStep": "B1"},
	})
	sse.send(StepEvent{Direction: "B", Step: "B1-3", Status: "running", Title: "验证Client身份证书"})
	sse.send(StepEvent{Direction: "B", Step: "B1-3", Status: "success",
		Title: "验证Client身份证书", Details: map[string]string{"parentStep": "B1"},
	})

	// Look up the client identity by hostname
	identity, found := a.findIdentity(clientHost)
	if !found {
		a3Dur := durationMs(time.Since(a3Start))
		sse.send(StepEvent{Direction: "A", Step: "A3", Status: "failed",
			Title: "PKI认证", DurationMs: a3Dur,
			Error: map[string]string{"type": "ConfigError", "message": fmt.Sprintf("no identity configured for %s", clientHost)},
		})
		return
	}

	// Now actually perform the mTLS connection
	opts := []ati.AgentClientOption{
		ati.WithTrustLevel(clientLevel),
		ati.WithClientTimeout(30 * time.Second),
		ati.WithIdentityCert(identity.CertFile, identity.KeyFile),
	}
	if serverVersion != "" {
		opts = append(opts, ati.WithTargetVersion(serverVersion))
	}

	client, err := ati.NewAgentClient(opts...)
	if err != nil {
		a3Dur := durationMs(time.Since(a3Start))
		sse.send(StepEvent{Direction: "A", Step: "A3", Status: "failed",
			Title: "PKI认证", DurationMs: a3Dur,
			Error: map[string]string{"type": "ClientError", "message": err.Error()},
		})
		return
	}

	targetURL := fmt.Sprintf("https://%s:%s/.well-known/agent.json", agentHost, a.proxyPort)
	resp, err := client.Get(ctx, targetURL)
	if err != nil {
		a3Dur := durationMs(time.Since(a3Start))

		errMsg := err.Error()
		errType := "HandshakeError"
		if strings.Contains(errMsg, "tls:") || strings.Contains(errMsg, "certificate") {
			if serverErr := a.fetchLastHandshakeError(); serverErr != "" {
				errMsg = serverErr
				errType = "ServerVerificationFailed"
			}
		}

		sse.send(StepEvent{Direction: "B", Step: "B1-4", Status: "failed",
			Title:   "双向认证加密通道已建立",
			Details: map[string]string{"parentStep": "B1"},
			Error:   map[string]string{"type": errType, "message": errMsg},
		})
		sse.send(StepEvent{Direction: "B", Step: "B1", Status: "failed",
			Title: "PKI认证", DurationMs: a3Dur,
			Error: map[string]string{"type": errType, "message": errMsg},
		})
		sse.send(StepEvent{Direction: "A", Step: "A3", Status: "failed",
			Title: "PKI认证", DurationMs: a3Dur,
			Error: map[string]string{"type": errType, "message": errMsg},
		})
		return
	}
	defer resp.Body.Close()

	// B1-4: mTLS established
	sse.send(StepEvent{Direction: "B", Step: "B1-4", Status: "success",
		Title: "双向认证加密通道已建立", Details: map[string]string{"parentStep": "B1"},
	})
	sse.send(StepEvent{Direction: "B", Step: "B1", Status: "success",
		Title: "PKI认证", DurationMs: durationMs(time.Since(a3Start)),
	})

	// A3d: mTLS tunnel
	sse.send(StepEvent{Direction: "A", Step: "A3d", Status: "success",
		Title: "双向认证加密通道已建立", DurationMs: durationMs(time.Since(a3Start)),
		Details: map[string]string{"parentStep": "A3"},
	})

	// A3e: handshake complete
	a3Dur := durationMs(time.Since(a3Start))
	sse.send(StepEvent{Direction: "A", Step: "A3e", Status: "success",
		Title: "双向身份认证完成", DurationMs: a3Dur,
		Details: map[string]string{"parentStep": "A3"},
	})
	sse.send(StepEvent{Direction: "A", Step: "A3", Status: "success",
		Title: "PKI认证", DurationMs: a3Dur,
		SdkApi: "mTLS Handshake",
	})

	// --- B2: 凭证认证 (server side, badge only) ---
	srvLevel := parseTrustLevel(serverPolicy)
	if srvLevel >= ati.BadgeRequired {
		b2Start := time.Now()
		sse.send(StepEvent{Direction: "B", Step: "B2", Status: "running",
			Title: "凭证认证", SdkApi: "ClientVerifier.verify()",
		})

		// Fetch real verification status from proxy
		achievedLevel := ""
		var clientErrors []string
		var clientCertFP string
		if statusData := a.fetchProxyVerification(); statusData != nil {
			achievedLevel = statusData.AchievedLevel
			clientErrors = statusData.Errors
			clientCertFP = statusData.CertFingerprint
		}
		achievedTrust := parseTrustLevel(achievedLevel)

		// B2-1: Seal signature verification
		b2_1Status := "success"
		if achievedTrust < ati.BadgeRequired {
			b2_1Status = "failed"
		}
		sse.send(StepEvent{Direction: "B", Step: "B2-1", Status: b2_1Status,
			Title:  "注册信息签名验证",
			SdkApi: "SealVerifier.verify()",
			Details: map[string]string{
				"parentStep": "B2",
				"验证对象":       "Client Agent 注册信息的数字签名",
				"result":     boolToResult(achievedTrust >= ati.BadgeRequired),
			},
			DurationMs: durationMs(time.Since(b2Start)),
		})

		// B2-2: Merkle proof verification
		sse.send(StepEvent{Direction: "B", Step: "B2-2", Status: b2_1Status,
			Title:  "透明日志收录验证",
			SdkApi: "MerkleProofVerifier.verifyInclusion()",
			Details: map[string]string{
				"parentStep": "B2",
				"验证对象":       "Client Agent 注册信息已被透明日志收录",
				"result":     boolToResult(achievedTrust >= ati.BadgeRequired),
			},
			DurationMs: durationMs(time.Since(b2Start)),
		})

		// B2-3: Certificate fingerprint comparison
		badgeStatus := "success"
		badgeResult := "通过 — Client证书指纹与透明日志记录一致"
		if achievedTrust < ati.BadgeRequired {
			badgeStatus = "failed"
			badgeResult = "失败"
			if len(clientErrors) > 0 {
				badgeResult = "失败 — " + strings.Join(clientErrors, "; ")
			}
		}
		b2_3Details := map[string]string{
			"parentStep":     "B2",
			"Client证书SPKI哈希": clientCertFP,
			"result":         badgeResult,
		}
		sse.send(StepEvent{Direction: "B", Step: "B2-3", Status: badgeStatus,
			Title:      "证书指纹比对",
			SdkApi:     "ServerVerifier.verify()",
			Details:    b2_3Details,
			DurationMs: durationMs(time.Since(b2Start)),
		})

		b2Status := "success"
		if achievedTrust < ati.BadgeRequired {
			b2Status = "failed"
		}
		sse.send(StepEvent{Direction: "B", Step: "B2", Status: b2Status,
			Title:      "凭证认证",
			SdkApi:     "ClientVerifier.verify()",
			DurationMs: durationMs(time.Since(b2Start)),
		})

		// --- B3: DANE认证 (server side, only for DANE_AND_BADGE) ---
		if srvLevel >= ati.DANEAndBadge {
			b3Start := time.Now()
			sse.send(StepEvent{Direction: "B", Step: "B3", Status: "running",
				Title: "DANE认证", SdkApi: "DANEVerifier.verifyIdentity()",
			})

			daneStatus := "success"
			daneResult := "通过 — Client证书与DNS TLSA记录匹配"
			if achievedTrust < ati.DANEAndBadge {
				daneStatus = "failed"
				daneResult = "失败 — Client证书与DNS TLSA记录不匹配"
			}

			// B3-1: TLSA lookup
			sse.send(StepEvent{Direction: "B", Step: "B3-1", Status: daneStatus,
				Title:  "查询DNS TLSA记录",
				SdkApi: "DANEVerifier.lookupIdentityTLSA()",
				Details: map[string]string{
					"parentStep": "B3",
					"query":      "_ati-identity._tls." + clientHost,
					"验证对象":       "查询Client域名的TLSA身份绑定记录",
				},
				DurationMs: durationMs(time.Since(b3Start)),
			})

			// B3-2: TLSA comparison
			sse.send(StepEvent{Direction: "B", Step: "B3-2", Status: daneStatus,
				Title:  "证书与TLSA记录比对",
				SdkApi: "DANEVerifier.matchCertificate()",
				Details: map[string]string{
					"parentStep":     "B3",
					"Client证书SPKI哈希": clientCertFP,
					"TLSA记录query":    "_ati-identity._tls." + clientHost,
					"result":         daneResult,
				},
				DurationMs: durationMs(time.Since(b3Start)),
			})

			sse.send(StepEvent{Direction: "B", Step: "B3", Status: daneStatus,
				Title:      "DANE认证",
				SdkApi:     "DANEVerifier.verifyIdentity()",
				DurationMs: durationMs(time.Since(b3Start)),
			})
		}
	}

	// --- Complete A2 (凭证认证) with detailed verification data ---
	o := resp.VerificationOutcome
	if clientLevel >= ati.BadgeRequired {
		// Extract detailed data from badge outcome
		var sealAlgo, sealDigest, sealKeyID, sealSig string
		var merkleLeaf, merkleRoot string
		var merkleTreeSize, merkleLeafIndex int64
		var merklePathLen int
		var tlFingerprint, actualFingerprint string

		if o.BadgeOutcome != nil && o.BadgeOutcome.TLResponse != nil {
			tl := o.BadgeOutcome.TLResponse
			sealAlgo = tl.Seal.SignatureAlgorithm
			sealDigest = tl.Seal.DigestAlgorithm
			sealKeyID = tl.Seal.KeyID
			if len(tl.Seal.Signature) > 20 {
				sealSig = tl.Seal.Signature[:20] + "..."
			} else {
				sealSig = tl.Seal.Signature
			}
			merkleLeaf = tl.MerkleProof.LeafHash
			merkleRoot = tl.MerkleProof.RootHash
			merkleTreeSize = tl.MerkleProof.TreeSize
			merkleLeafIndex = tl.MerkleProof.LeafIndex
			merklePathLen = len(tl.MerkleProof.Path)
			tlFingerprint = tl.Payload.Certificates.ServerCertFingerprint
		}
		if o.BadgeOutcome != nil && o.BadgeOutcome.MatchedFingerprint != nil {
			actualFingerprint = o.BadgeOutcome.MatchedFingerprint.String()
		}

		// A2-1: Seal signature verification
		sse.send(StepEvent{Direction: "A", Step: "A2-1", Status: "success",
			Title: "注册信息签名验证", DurationMs: durationMs(time.Since(a2Start)),
			SdkApi: "SealVerifier.verify()",
			Details: map[string]string{
				"parentStep": "A2",
				"算法":         sealAlgo,
				"摘要":         sealDigest,
				"密钥ID":       sealKeyID,
				"签名":         sealSig,
				"result":     "通过",
			},
		})

		// A2-2: Merkle proof verification
		sse.send(StepEvent{Direction: "A", Step: "A2-2", Status: "success",
			Title: "透明日志收录验证", DurationMs: durationMs(time.Since(a2Start)),
			SdkApi: "MerkleProofVerifier.verifyInclusion()",
			Details: map[string]any{
				"parentStep": "A2",
				"leafHash":   merkleLeaf,
				"rootHash":   merkleRoot,
				"treeSize":   merkleTreeSize,
				"leafIndex":  merkleLeafIndex,
				"pathLength": merklePathLen,
				"result":     "通过",
			},
		})

		// A2-3: Extract server cert fingerprint from TL
		sse.send(StepEvent{Direction: "A", Step: "A2-3", Status: "success",
			Title: "提取Agent证书指纹", DurationMs: durationMs(time.Since(a2Start)),
			SdkApi: "TransparencyLog.getServerCertFingerprint()",
			Details: map[string]string{
				"parentStep": "A2",
				"透明日志记录的指纹":  tlFingerprint,
			},
		})

		// A2-4: Fingerprint comparison
		a2_4Status := "success"
		a2_4Result := "通过 — 证书指纹匹配"
		if !o.BadgeVerified {
			a2_4Status = "failed"
			a2_4Result = "失败 — 证书指纹不匹配"
		}
		sse.send(StepEvent{Direction: "A", Step: "A2-4", Status: a2_4Status,
			Title: "证书指纹比对", DurationMs: durationMs(time.Since(a2Start)),
			SdkApi: "ServerVerifier.verify()",
			Details: map[string]string{
				"parentStep": "A2",
				"透明日志指纹":     tlFingerprint,
				"实际Server指纹": actualFingerprint,
				"result":     a2_4Result,
			},
		})

		a2Status := "success"
		if !o.BadgeVerified {
			a2Status = "failed"
		}
		sse.send(StepEvent{Direction: "A", Step: "A2", Status: a2Status,
			Title: "凭证认证", DurationMs: durationMs(time.Since(a2Start)),
			SdkApi: "AtiVerifiedClient.connectAsync()",
		})
	}

	// --- Step A4: DANE认证 (only for DANE_AND_BADGE) ---
	if clientLevel >= ati.DANEAndBadge {
		a4Start := time.Now()
		sse.send(StepEvent{Direction: "A", Step: "A4", Status: "running",
			Title: "DANE认证", SdkApi: "DANEVerifier.verify()",
		})

		tlsaQuery := "_443._tcp." + agentHost
		var dnssecValid bool
		var tlsaRecordHash string
		var certHashUsed string
		var daneErrStr string

		if o.DANEDetails != nil {
			dnssecValid = o.DANEDetails.Type == verify.DANEVerified
			certHashUsed = o.DANEDetails.CertHashUsed
			if len(o.DANEDetails.Records) > 0 {
				tlsaRecordHash = o.DANEDetails.Records[0].CertHash
			}
			if o.DANEDetails.Error != nil {
				daneErrStr = o.DANEDetails.Error.Error()
			}
		}

		// A4-1: TLSA DNS lookup + DNSSEC chain validation
		a4_1Status := "success"
		if !o.DANEVerified && daneErrStr != "" {
			a4_1Status = "failed"
		}
		a4_1Details := map[string]string{
			"parentStep": "A4",
			"query":      tlsaQuery,
			"DNSSEC验证":   boolToResult(dnssecValid),
		}
		if tlsaRecordHash != "" {
			a4_1Details["TLSA记录哈希"] = tlsaRecordHash
		}
		if daneErrStr != "" {
			a4_1Details["error"] = daneErrStr
		}
		sse.send(StepEvent{Direction: "A", Step: "A4-1", Status: a4_1Status,
			Title: "查询TLSA记录 + DNSSEC链验证", DurationMs: durationMs(time.Since(a4Start)),
			SdkApi:  "DANEVerifier.lookupTLSA()",
			Details: a4_1Details,
		})

		// A4-2: Compare server cert hash with TLSA record
		a4_2Status := "success"
		a4_2Result := "通过 — 哈希匹配"
		if !o.DANEVerified {
			a4_2Status = "failed"
			a4_2Result = "失败 — 哈希不匹配"
		}
		sse.send(StepEvent{Direction: "A", Step: "A4-2", Status: a4_2Status,
			Title: "证书与TLSA记录比对", DurationMs: durationMs(time.Since(a4Start)),
			SdkApi: "DANEVerifier.matchCertificate()",
			Details: map[string]string{
				"parentStep":   "A4",
				"TLSA记录哈希":     tlsaRecordHash,
				"Server实际证书哈希": certHashUsed,
				"result":       a4_2Result,
			},
		})

		a4Status := "success"
		if !o.DANEVerified {
			a4Status = "failed"
		}
		sse.send(StepEvent{Direction: "A", Step: "A4", Status: a4Status,
			Title: "DANE认证", DurationMs: durationMs(time.Since(a4Start)),
			SdkApi: "DANEVerifier.verify()",
		})
	}

	// Store client for chat
	a.mu.Lock()
	a.client = client
	a.connected = true
	a.agentHost = agentHost
	a.mu.Unlock()

	// Final connected event
	sse.send(StepEvent{
		Step:   "connected",
		Status: "success",
		Title:  "连接成功",
		Details: map[string]any{
			"atiName":     o.PeerATIName,
			"policy":      clientLevel.String(),
			"targetAgent": agentHost,
			"clientHost":  clientHost,
		},
	})
}

// findIdentity returns the client identity matching the given hostname.
func (a *App) findIdentity(host string) (clientIdentity, bool) {
	for _, id := range a.identities {
		if strings.EqualFold(id.Host, host) {
			return id, true
		}
	}
	return clientIdentity{}, false
}

// handleClientIdentities returns the list of configured client identities.
func (a *App) handleClientIdentities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.identities)
}

// fetchLastHandshakeError queries the proxy status API for the most recent TLS handshake error.
func (a *App) fetchLastHandshakeError() string {
	resp, err := http.Get(a.proxyAPIAddr + "/api/status")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var status struct {
		LastHandshakeError string `json:"lastHandshakeError"`
	}
	if json.NewDecoder(resp.Body).Decode(&status) != nil {
		return ""
	}
	return status.LastHandshakeError
}

// fetchProxyVerification queries the proxy status API and returns the first client's verification info.
func (a *App) fetchProxyVerification() *proxyClientInfo {
	resp, err := http.Get(a.proxyAPIAddr + "/api/status")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var status struct {
		ConnectedClients []proxyClientInfo `json:"connectedClients"`
		ServerPolicy     string            `json:"serverPolicy"`
	}
	if json.NewDecoder(resp.Body).Decode(&status) != nil {
		return nil
	}
	if len(status.ConnectedClients) == 0 {
		return nil
	}
	return &status.ConnectedClients[0]
}

type proxyClientInfo struct {
	SourceIP        string   `json:"sourceIp"`
	AgentHost       string   `json:"agentHost"`
	Policy          string   `json:"policy"`
	Verified        bool     `json:"verified"`
	AchievedLevel   string   `json:"achievedLevel"`
	CertFingerprint string   `json:"certFingerprint"`
	Errors          []string `json:"errors"`
}

// --- Chat: agentA orchestration over mTLS to agentB ---

// oaMessage / oaToolCall mirror the OpenAI-compatible chat schema used by
// DashScope. agentA runs a tool-calling loop where the only tool is
// ask_agent_b, which forwards a question to agentB through the mTLS tunnel.
type oaMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function oaFunctionCall `json:"function"`
}

type oaFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// chatEvent is streamed to the browser over SSE during orchestration.
type chatEvent struct {
	Type string `json:"type"` // "turn" | "summary" | "error"
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	Text string `json:"text"`
}

func orchestratorSystemPrompt(city string) string {
	return fmt.Sprintf(`你是 Agent A，一个出行规划助手，正在代表最终用户与另一个专家 Agent（Agent B）协作。
用户所在城市是「%s」。用户只会给你一句比较模糊的需求（例如"今天好无聊，有什么地方推荐去玩？"）。
你自己不掌握天气数据，也不了解当地有哪些具体地点，必须通过调用 ask_agent_b 工具向 Agent B 询问来获取信息。
请按以下流程自主完成，不要一次性把所有问题塞进一次提问，要分多轮：
1. 先用 ask_agent_b 询问「%s」今天/未来几天的天气。
2. 拿到天气后，再用 ask_agent_b 结合天气询问适合去哪里玩（例如晴天问有哪些山可以爬，雨天问有哪些商场/室内景点可以逛）。
3. 可以再追问 1-2 轮细节（例如某个地点的具体情况、交通、耗时）。
4. 至少与 Agent B 交互 3 轮以上，信息足够后，直接输出给用户的最终总结（不要再调用工具）。
最终总结要面向用户、条理清晰，包含三部分：① 今天天气如何；② 推荐去哪里玩（具体地点+理由）；③ 一个大致的时间计划安排。
每次调用 ask_agent_b 时，问题要具体、简短、口语化。`, city, city)
}

func askAgentBTool() []map[string]any {
	return []map[string]any{
		{
			"type": "function",
			"function": map[string]any{
				"name":        "ask_agent_b",
				"description": "向掌握真实天气数据与本地出行信息的 Agent B 提问，获取天气或地点推荐等信息",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"question": map[string]any{
							"type":        "string",
							"description": "要问 Agent B 的具体问题，例如「杭州今天天气怎么样？」或「这种天气适合爬哪些山？」",
						},
					},
					"required": []string{"question"},
				},
			},
		},
	}
}

func (a *App) handleChatStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(ev chatEvent) {
		data, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	a.mu.Lock()
	client := a.client
	connected := a.connected
	a.mu.Unlock()

	if !connected || client == nil {
		send(chatEvent{Type: "error", Text: "尚未连接，请先完成 Agent 认证"})
		return
	}

	message := strings.TrimSpace(r.URL.Query().Get("message"))
	city := strings.TrimSpace(r.URL.Query().Get("city"))
	if city == "" {
		city = "北京"
	}
	if message == "" {
		send(chatEvent{Type: "error", Text: "请输入你的问题"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()

	// Degraded mode: no LLM key — just relay the question to agentB directly.
	if a.dashKey == "" {
		answer, err := a.askAgentB(ctx, client, message)
		if err != nil {
			send(chatEvent{Type: "error", Text: "调用 Agent B 失败：" + err.Error()})
			return
		}
		send(chatEvent{Type: "turn", From: "A", To: "B", Text: message})
		send(chatEvent{Type: "turn", From: "B", To: "A", Text: answer})
		send(chatEvent{Type: "summary", Text: "（未配置模型密钥，直接转发 Agent B 的回答）\n\n" + answer})
		return
	}

	messages := []oaMessage{
		{Role: "system", Content: orchestratorSystemPrompt(city)},
		{Role: "user", Content: message},
	}

	const maxRounds = 6
	for round := 0; round < maxRounds; round++ {
		msg, err := a.callLLM(ctx, messages)
		if err != nil {
			send(chatEvent{Type: "error", Text: "Agent A 思考失败：" + err.Error()})
			return
		}
		messages = append(messages, msg)

		if len(msg.ToolCalls) == 0 {
			text := strings.TrimSpace(msg.Content)
			if text == "" {
				text = "抱歉，我暂时没能整理出建议，换个说法再试试？"
			}
			send(chatEvent{Type: "summary", Text: text})
			return
		}

		for _, tc := range msg.ToolCalls {
			var args struct {
				Question string `json:"question"`
			}
			json.Unmarshal([]byte(tc.Function.Arguments), &args)
			question := strings.TrimSpace(args.Question)
			if question == "" {
				question = message
			}

			send(chatEvent{Type: "turn", From: "A", To: "B", Text: question})

			answer, err := a.askAgentB(ctx, client, question)
			if err != nil {
				answer = "（Agent B 调用失败：" + err.Error() + "）"
			}
			slog.Info("[chat] agentA<->agentB round", "round", round, "q", question)
			send(chatEvent{Type: "turn", From: "B", To: "A", Text: answer})

			messages = append(messages, oaMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    answer,
			})
		}
	}

	// Ran out of rounds — force a final summary from the collected context.
	messages = append(messages, oaMessage{
		Role:    "user",
		Content: "请基于以上与 Agent B 的对话，现在直接给我最终总结（今天天气、推荐去哪玩、时间计划），不要再调用工具。",
	})
	final, err := a.callLLM(ctx, messages)
	if err != nil {
		send(chatEvent{Type: "error", Text: "生成总结失败：" + err.Error()})
		return
	}
	text := strings.TrimSpace(final.Content)
	if text == "" {
		text = "抱歉，这次没能整理出完整建议，可以再问我一次吗？"
	}
	send(chatEvent{Type: "summary", Text: text})
}

// askAgentB forwards a single question to agentB through the mTLS tunnel,
// reusing the shared conversationId so agentB retains context across rounds.
func (a *App) askAgentB(ctx context.Context, client *ati.AgentClient, question string) (string, error) {
	a.mu.Lock()
	agentHost := a.agentHost
	conversationID := a.conversationID
	a.mu.Unlock()

	chatReq := map[string]any{
		"message":        question,
		"conversationId": conversationID,
		"user":           "agent-a",
	}
	targetURL := fmt.Sprintf("https://%s:%s/chat", agentHost, a.proxyPort)

	resp, err := client.Post(ctx, targetURL, chatReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var chatResp struct {
		Reply          string `json:"reply"`
		ConversationID string `json:"conversationId"`
	}
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("invalid agentB response: %w", err)
	}
	if chatResp.ConversationID != "" {
		a.mu.Lock()
		a.conversationID = chatResp.ConversationID
		a.mu.Unlock()
	}
	return chatResp.Reply, nil
}

// callLLM invokes DashScope with the ask_agent_b tool and returns the assistant message.
func (a *App) callLLM(ctx context.Context, messages []oaMessage) (oaMessage, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"model":       a.dashModel,
		"messages":    messages,
		"tools":       askAgentBTool(),
		"tool_choice": "auto",
	})

	const dashScopeURL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", dashScopeURL, bytes.NewReader(reqBody))
	if err != nil {
		return oaMessage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.dashKey)

	resp, err := a.llmHTTP.Do(req)
	if err != nil {
		return oaMessage{}, fmt.Errorf("dashscope request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return oaMessage{}, fmt.Errorf("dashscope returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message oaMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return oaMessage{}, fmt.Errorf("dashscope response parse error: %w", err)
	}
	if len(result.Choices) == 0 {
		return oaMessage{}, fmt.Errorf("dashscope returned no choices")
	}
	msg := result.Choices[0].Message
	msg.Role = "assistant"
	return msg, nil
}

// handleChat is kept as a non-streaming fallback that relays one message to agentB.
func (a *App) handleChat(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	client := a.client
	connected := a.connected
	a.mu.Unlock()

	if !connected || client == nil {
		writeJSON(w, map[string]string{"status": "error", "reply": "not connected"})
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"status": "error", "reply": "invalid request"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	reply, err := a.askAgentB(ctx, client, req.Message)
	if err != nil {
		writeJSON(w, map[string]string{"status": "error", "reply": "chat request failed: " + err.Error()})
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "reply": reply})
}

// --- Disconnect ---

func (a *App) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	agentHost := r.URL.Query().Get("agentHost")
	if agentHost == "" {
		agentHost = "ats-server.asia"
	}

	// Clear proxy tracking via local API
	clearReq, _ := http.NewRequest("POST", a.proxyAPIAddr+"/api/clear", nil)
	http.DefaultClient.Do(clearReq)

	a.mu.Lock()
	a.client = nil
	a.connected = false
	a.agentHost = ""
	a.conversationID = ""
	a.mu.Unlock()

	writeJSON(w, map[string]string{"status": "disconnected"})
}

// --- Proxy Status Relay ---

func (a *App) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	proxyResp, err := http.Get(a.proxyAPIAddr + "/api/status")
	if err != nil {
		writeJSON(w, map[string]any{"connectedClients": []any{}, "serverPolicy": ""})
		return
	}
	defer proxyResp.Body.Close()
	body, _ := io.ReadAll(proxyResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (a *App) handleServerPolicy(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	proxyURL := a.proxyAPIAddr + "/api/config/policy"
	proxyReq, _ := http.NewRequest("PUT", proxyURL, bytes.NewReader(body))
	proxyReq.Header.Set("Content-Type", "application/json")

	proxyResp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		writeJSON(w, map[string]string{"status": "error", "message": err.Error()})
		return
	}
	defer proxyResp.Body.Close()
	respBody, _ := io.ReadAll(proxyResp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

// --- Debug Logging ---

func (a *App) handleDebugLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.debugLog.getLogs())
}

func (a *App) handleDebugToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	a.debugLog.setEnabled(req.Enabled)
	writeJSON(w, map[string]any{"status": "ok", "debugEnabled": req.Enabled})
}

func (a *App) handleDebugClear(w http.ResponseWriter, r *http.Request) {
	a.debugLog.clear()
	writeJSON(w, map[string]string{"status": "ok"})
}

// DebugLogCollector captures slog records for the debug panel.
type DebugLogCollector struct {
	mu      sync.Mutex
	logs    []DebugLogEntry
	enabled bool
}

type DebugLogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Category  string `json:"category"`
	Message   string `json:"message"`
}

func newDebugLogCollector() *DebugLogCollector {
	return &DebugLogCollector{}
}

func (d *DebugLogCollector) setEnabled(enabled bool) {
	d.mu.Lock()
	d.enabled = enabled
	d.mu.Unlock()
}

func (d *DebugLogCollector) getLogs() []DebugLogEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DebugLogEntry, len(d.logs))
	copy(out, d.logs)
	return out
}

func (d *DebugLogCollector) clear() {
	d.mu.Lock()
	d.logs = nil
	d.mu.Unlock()
}

func (d *DebugLogCollector) addLog(category, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled {
		return
	}
	if len(d.logs) >= 500 {
		d.logs = d.logs[1:]
	}
	d.logs = append(d.logs, DebugLogEntry{
		Timestamp: time.Now().UnixMilli(),
		Category:  category,
		Message:   message,
	})
}

// slog.Handler implementation
func (d *DebugLogCollector) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (d *DebugLogCollector) Handle(_ context.Context, record slog.Record) error {
	var sb strings.Builder
	sb.WriteString(record.Message)
	record.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(fmt.Sprintf("%v", a.Value.Any()))
		return true
	})

	msg := sb.String()
	category := categorizeLog(record.Message)

	d.addLog(category, msg)

	// Also write to stderr
	fmt.Fprintf(os.Stderr, "%s %s %s\n", record.Time.Format("15:04:05"), record.Level, msg)
	return nil
}

func (d *DebugLogCollector) WithAttrs(_ []slog.Attr) slog.Handler { return d }
func (d *DebugLogCollector) WithGroup(_ string) slog.Handler      { return d }

func categorizeLog(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "[server-verify]"):
		return "SDK_AGENT"
	case strings.Contains(lower, "[verify]"):
		return "SDK_TL"
	case strings.Contains(lower, "discovery"), strings.Contains(lower, "agent discovery"):
		return "SDK_DISCOVERY"
	case strings.Contains(lower, "connect"):
		return "CONNECT"
	case strings.Contains(lower, "mcp"), strings.Contains(lower, "tools"):
		return "MCP"
	case strings.Contains(lower, "error"), strings.Contains(lower, "failed"):
		return "ERROR"
	default:
		return "CHAT"
	}
}

func parseTrustLevel(s string) ati.TrustLevel {
	switch strings.ToLower(s) {
	case "pki_only", "pki":
		return ati.PKIOnly
	case "badge_required", "badge":
		return ati.BadgeRequired
	case "dane_and_badge", "dane":
		return ati.DANEAndBadge
	default:
		return ati.BadgeRequired
	}
}

func boolToResult(pass bool) string {
	if pass {
		return "通过"
	}
	return "失败"
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
