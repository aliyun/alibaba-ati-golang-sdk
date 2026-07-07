// Package proxy implements the ATI demo mTLS termination proxy. It fronts the
// weather agent backend: the mTLS server on ListenAddr verifies the client
// agent's identity (PKI / Badge / DANE) and forwards /chat and /mcp to the
// backend, while a plain-HTTP API on APIListenAddr exposes status and lets the
// server-side trust policy be updated at runtime.
package proxy

import (
	"context"
	crypto_tls "crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"
)

// Config holds the proxy's runtime configuration.
type Config struct {
	ListenAddr    string // mTLS listen address (default :7443)
	APIListenAddr string // plain HTTP API listen address (default :7444)
	CertFile      string
	KeyFile       string
	CABundle      string
	TrustLevel    string // client verification level: pki_only, badge, dane
	BackendURL    string // backend agent URL (default http://localhost:7100)
}

// Run starts the proxy's mTLS and API servers and blocks forever.
func Run(cfg Config) error {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":7443"
	}
	if cfg.APIListenAddr == "" {
		cfg.APIListenAddr = ":7444"
	}
	if cfg.TrustLevel == "" {
		cfg.TrustLevel = "pki_only"
	}
	if cfg.BackendURL == "" {
		cfg.BackendURL = "http://localhost:7100"
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return fmt.Errorf("proxy: cert and key are required")
	}

	proxy := &Proxy{
		certFile:      cfg.CertFile,
		keyFile:       cfg.KeyFile,
		caBundle:      cfg.CABundle,
		backendURL:    cfg.BackendURL,
		listenAddr:    cfg.ListenAddr,
		apiListenAddr: cfg.APIListenAddr,
		tracker:       newConnectionTracker(cfg.TrustLevel),
		peerLevels:    &sync.Map{},
	}

	// Start plain HTTP API server (no mTLS) for status/policy endpoints
	go proxy.startAPIServer()

	// Run mTLS server in a goroutine so Run() doesn't exit on policy-triggered restarts
	go proxy.startServer()

	select {}
}

// Proxy is the mTLS termination proxy.
type Proxy struct {
	certFile      string
	keyFile       string
	caBundle      string
	backendURL    string
	listenAddr    string
	apiListenAddr string
	tracker       *ConnectionTracker
	peerLevels    *sync.Map

	mu     sync.Mutex
	server *http.Server
}

func (p *Proxy) startServer() {
	p.mu.Lock()
	oldServer := p.server
	p.mu.Unlock()

	if oldServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		oldServer.Shutdown(ctx)
		cancel()
	}

	trustLevel := parseTrustLevel(p.tracker.getPolicy())

	serverOpts := []ati.ServerOption{
		ati.WithServerCert(p.certFile, p.keyFile),
		ati.WithClientVerifier(trustLevel),
		ati.WithPeerLevelStore(p.peerLevels),
	}
	if p.caBundle != "" {
		serverOpts = append(serverOpts, ati.WithClientCA(p.caBundle))
	}

	tlsConfig, err := ati.NewServerTLSConfig(serverOpts...)
	if err != nil {
		slog.Error("[proxy] TLS config failed", "error", err)
		return
	}

	origVerify := tlsConfig.VerifyConnection
	if origVerify != nil {
		tlsConfig.VerifyConnection = func(cs crypto_tls.ConnectionState) error {
			err := origVerify(cs)
			if err != nil {
				p.tracker.recordHandshakeError(err.Error())
				var agentHost string
				if len(cs.PeerCertificates) > 0 {
					if peer, nameErr := ati.PeerATIName(&cs); nameErr == nil {
						agentHost = peer.Host
					}
				}
				p.tracker.recordClient("unknown", agentHost, false, "", "", []string{err.Error()})
			}
			return err
		}
	}

	mux := http.NewServeMux()

	// Agent card + MCP/Chat forwarding — all require valid client cert (mTLS)
	mux.HandleFunc("GET /.well-known/agent.json", p.handleAgentCard)
	mux.HandleFunc("POST /mcp", p.handleMCPForward)
	mux.HandleFunc("POST /chat", p.handleChatForward)

	handler := p.clientTrackingMiddleware(mux)

	server := &http.Server{
		Addr:      p.listenAddr,
		TLSConfig: tlsConfig,
		Handler:   handler,
	}

	p.mu.Lock()
	p.server = server
	p.mu.Unlock()

	slog.Info("[proxy] starting", "addr", server.Addr, "trust", p.tracker.getPolicy(), "backend", p.backendURL)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		slog.Error("[proxy] server failed", "error", err)
	}
}

// startAPIServer starts a plain HTTP server for status/policy endpoints (no mTLS).
func (p *Proxy) startAPIServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", p.handleStatus)
	mux.HandleFunc("POST /api/clear", p.handleClear)
	mux.HandleFunc("PUT /api/config/policy", p.handlePolicyUpdate)
	mux.HandleFunc("OPTIONS /", p.handleCORS)

	handler := p.corsMiddleware(mux)

	slog.Info("[proxy] API server starting", "addr", p.apiListenAddr)
	if err := http.ListenAndServe(p.apiListenAddr, handler); err != nil {
		slog.Error("[proxy] API server failed", "error", err)
	}
}

// clientTrackingMiddleware records connected clients on the mTLS server.
func (p *Proxy) clientTrackingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceIP := r.RemoteAddr
		if idx := strings.LastIndex(sourceIP, ":"); idx > 0 {
			sourceIP = sourceIP[:idx]
		}

		var agentHost string
		var verified bool
		var peerErrors []string
		var certFingerprint string

		var achievedLevel string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			verified = true
			if peer, err := ati.PeerATIName(r.TLS); err == nil {
				agentHost = peer.Host
			}
			if level := ati.PeerTrustLevel(r.TLS, p.peerLevels); level != nil {
				achievedLevel = level.String()
			}
			certFingerprint = verify.CertIdentityFromX509(r.TLS.PeerCertificates[0]).SPKIFingerprint.ToHex()
		} else {
			peerErrors = append(peerErrors, "no client certificate")
		}

		p.tracker.recordClient(sourceIP, agentHost, verified, achievedLevel, certFingerprint, peerErrors)

		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (p *Proxy) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"name":        "ATI Demo Weather Agent",
		"description": "ATI SDK demo proxy fronting a weather-forecast agent",
		"version":     "1.0.0",
		"url":         fmt.Sprintf("https://localhost%s/chat", p.listenAddr),
		"capabilities": map[string]any{
			"streaming": false,
		},
		"skills": []map[string]string{
			{"id": "weather", "name": "Weather", "description": "查询城市天气预报并给出出行建议"},
		},
	})
}

func (p *Proxy) handleMCPForward(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var rpcReq struct {
		Method string `json:"method"`
	}
	json.Unmarshal(body, &rpcReq)

	backendReq, err := http.NewRequestWithContext(r.Context(), "POST", p.backendURL+"/mcp", strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "failed to create backend request", http.StatusInternalServerError)
		return
	}
	backendReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(backendReq)
	if err != nil {
		slog.Error("[proxy] backend request failed", "error", err)
		p.tracker.recordMCPLog(rpcReq.Method, 502)
		http.Error(w, "backend error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.tracker.recordMCPLog(rpcReq.Method, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

// handleChatForward is a pure mTLS-terminating forwarder: it relays the client
// agent's chat request straight to the backend weather agent's /chat endpoint
// and streams the JSON reply back unchanged.
func (p *Proxy) handleChatForward(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	backendReq, err := http.NewRequestWithContext(r.Context(), "POST", p.backendURL+"/chat", strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "failed to create backend request", http.StatusInternalServerError)
		return
	}
	backendReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(backendReq)
	if err != nil {
		slog.Error("[proxy] backend chat request failed", "error", err)
		p.tracker.recordMCPLog("chat", 502)
		http.Error(w, "backend error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.tracker.recordMCPLog("chat", resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

func (p *Proxy) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, p.tracker.status())
}

func (p *Proxy) handleClear(w http.ResponseWriter, r *http.Request) {
	p.tracker.clear()
	writeJSON(w, map[string]string{"status": "ok"})
}

func (p *Proxy) handlePolicyUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]string{"status": "error", "message": "invalid request"})
		return
	}

	level := parseTrustLevel(req.Policy)
	p.tracker.setPolicy(level.String())
	slog.Info("[proxy] policy updated, restarting", "policy", level.String())

	go p.startServer()

	writeJSON(w, map[string]string{"status": "ok", "policy": level.String()})
}

// ConnectionTracker tracks connected clients and MCP logs.
type ConnectionTracker struct {
	mu                 sync.Mutex
	clients            map[string]*ClientInfo
	mcpLogs            []McpLogEntry
	policy             string
	lastHandshakeError string
}

type ClientInfo struct {
	SourceIP        string   `json:"sourceIp"`
	AgentHost       string   `json:"agentHost"`
	Policy          string   `json:"policy"`
	Verified        bool     `json:"verified"`
	AchievedLevel   string   `json:"achievedLevel,omitempty"`
	CertFingerprint string   `json:"certFingerprint,omitempty"`
	Errors          []string `json:"errors,omitempty"`
}

type McpLogEntry struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Status int    `json:"status"`
}

type StatusResponse struct {
	ConnectedClients   []*ClientInfo `json:"connectedClients"`
	McpLogs            []McpLogEntry `json:"mcpLogs"`
	ServerPolicy       string        `json:"serverPolicy"`
	LastHandshakeError string        `json:"lastHandshakeError,omitempty"`
}

func newConnectionTracker(policy string) *ConnectionTracker {
	return &ConnectionTracker{
		clients: make(map[string]*ClientInfo),
		policy:  parseTrustLevel(policy).String(),
	}
}

func (t *ConnectionTracker) recordClient(sourceIP, agentHost string, verified bool, achievedLevel, certFingerprint string, errors []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if verified {
		delete(t.clients, "unknown")
		t.lastHandshakeError = ""
	}
	t.clients[sourceIP] = &ClientInfo{
		SourceIP:        sourceIP,
		AgentHost:       agentHost,
		Policy:          t.policy,
		Verified:        verified,
		AchievedLevel:   achievedLevel,
		CertFingerprint: certFingerprint,
		Errors:          errors,
	}
}

func (t *ConnectionTracker) recordHandshakeError(errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clients = make(map[string]*ClientInfo)
	t.lastHandshakeError = errMsg
}

func (t *ConnectionTracker) recordMCPLog(method string, status int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mcpLogs = append(t.mcpLogs, McpLogEntry{
		Time:   time.Now().Format("15:04:05"),
		Method: method,
		Status: status,
	})
}

func (t *ConnectionTracker) getPolicy() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.policy
}

func (t *ConnectionTracker) setPolicy(policy string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.policy = policy
}

func (t *ConnectionTracker) status() StatusResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	clients := make([]*ClientInfo, 0, len(t.clients))
	for _, c := range t.clients {
		clients = append(clients, c)
	}
	return StatusResponse{
		ConnectedClients:   clients,
		McpLogs:            t.mcpLogs,
		ServerPolicy:       t.policy,
		LastHandshakeError: t.lastHandshakeError,
	}
}

func (t *ConnectionTracker) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clients = make(map[string]*ClientInfo)
	t.mcpLogs = nil
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
		return ati.PKIOnly
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
