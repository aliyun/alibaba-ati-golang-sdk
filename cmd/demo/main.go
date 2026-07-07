package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
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
)

//go:embed index.html
var staticFS embed.FS

func main() {
	var (
		listenAddr = flag.String("listen", ":8080", "web demo listen address")
		certFile   = flag.String("cert", "", "client identity certificate PEM")
		keyFile    = flag.String("key", "", "client private key PEM")
		caBundle   = flag.String("ca-bundle", "", "CA bundle for server to verify client certs (same as --server-ca)")

		serverCert       = flag.String("server-cert", "", "server TLS certificate PEM")
		serverKey        = flag.String("server-key", "", "server TLS private key PEM")
		serverAddr       = flag.String("server-listen", ":8443", "built-in ATI server listen address")
		serverTrustLevel = flag.String("server-trust", "pki_only", "server client verification level: pki_only, badge, dane")
		serverCA         = flag.String("server-ca", "", "CA bundle for server to verify client certs (optional)")
		backendURL       = flag.String("backend", "", "backend AI agent URL (e.g. https://dns-ai-platform.aliyun-inc.com/v1/agent-messages)")
	)
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("--cert and --key are required")
	}
	if *serverCert == "" || *serverKey == "" {
		log.Fatal("--server-cert and --server-key are required")
	}

	// --ca-bundle and --server-ca both serve the same purpose: CA for server to verify client certs
	clientCA := *serverCA
	if clientCA == "" {
		clientCA = *caBundle
	}

	app := &App{
		certFile:         *certFile,
		keyFile:          *keyFile,
		serverCertFile:   *serverCert,
		serverKeyFile:    *serverKey,
		serverCA:         clientCA,
		backendURL:       *backendURL,
		serverTrustLevel: *serverTrustLevel,
		serverListenAddr: *serverAddr,
		logHub:           newLogHub(),
	}

	// Capture slog output for SSE streaming
	slog.SetDefault(slog.New(app.logHub))

	// Start built-in ATI server (Proxy)
	go app.startATIServer()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleIndex)
	mux.HandleFunc("POST /api/connect", app.handleConnect)
	mux.HandleFunc("POST /api/send", app.handleSend)
	mux.HandleFunc("POST /api/disconnect", app.handleDisconnect)
	mux.HandleFunc("GET /api/logs", app.handleLogs)
	mux.HandleFunc("GET /api/status", app.handleStatus)

	log.Printf("ATI Demo Web UI on %s", *listenAddr)
	log.Printf("ATI Server (Proxy) on %s (trust: %s)", *serverAddr, *serverTrustLevel)
	log.Fatal(http.ListenAndServe(*listenAddr, mux))
}


// makeBackendA2AHandler creates an A2A handler that forwards to a real AI backend.
func makeBackendA2AHandler(backendURL string) http.HandlerFunc {
	token := os.Getenv("BACKEND_TOKEN")

	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      any             `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		json.Unmarshal(body, &req)

		var params struct {
			Message struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"message"`
		}
		json.Unmarshal(req.Params, &params)

		inputText := ""
		for _, p := range params.Message.Parts {
			inputText += p.Text
		}

		peerName := "unknown"
		if peer, err := ati.PeerATIName(r.TLS); err == nil {
			peerName = peer.Raw
		}
		slog.Info("[server] A2A request", "peer", peerName, "text", inputText)

		// Call backend
		backendReq := map[string]any{
			"query":           inputText,
			"conversation_id": fmt.Sprintf("demo-%d", time.Now().UnixMilli()),
			"user":            peerName,
			"response_mode":   "blocking",
			"inputs":          map[string]any{},
		}
		backendBody, _ := json.Marshal(backendReq)

		httpReq, _ := http.NewRequestWithContext(r.Context(), "POST", backendURL, strings.NewReader(string(backendBody)))
		httpReq.Header.Set("Content-Type", "application/json")
		if token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			slog.Error("[server] backend call failed", "error", err)
			writeA2AError(w, req.ID, -32000, "backend error: "+err.Error())
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)

		// Try to extract answer from backend response
		answer := extractBackendAnswer(respBody)
		if answer == "" {
			answer = string(respBody)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"id":        fmt.Sprintf("task-%d", time.Now().UnixMilli()),
				"contextId": fmt.Sprintf("ctx-%d", time.Now().UnixMilli()),
				"status":    map[string]string{"state": "completed"},
				"artifacts": []map[string]any{
					{"parts": []map[string]string{{"type": "text", "text": answer}}},
				},
			},
		})
	}
}

func extractBackendAnswer(body []byte) string {
	// Try common response formats
	var resp struct {
		Answer string `json:"answer"`
	}
	if json.Unmarshal(body, &resp) == nil && resp.Answer != "" {
		return resp.Answer
	}

	var resp2 struct {
		Data struct {
			Answer string `json:"answer"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &resp2) == nil && resp2.Data.Answer != "" {
		return resp2.Data.Answer
	}

	var resp3 struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &resp3) == nil && len(resp3.Choices) > 0 {
		return resp3.Choices[0].Message.Content
	}

	return ""
}

func writeA2AError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	})
}

// makeEchoA2AHandler creates a simple echo A2A handler (no backend).
func makeEchoA2AHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      any             `json:"id"`
			Params  json.RawMessage `json:"params"`
		}
		json.Unmarshal(body, &req)

		var params struct {
			Message struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"message"`
		}
		json.Unmarshal(req.Params, &params)

		inputText := ""
		for _, p := range params.Message.Parts {
			inputText += p.Text
		}

		peerName := "unknown"
		if peer, err := ati.PeerATIName(r.TLS); err == nil {
			peerName = peer.Raw
		}

		reply := fmt.Sprintf("[Echo] %s (peer: %s)", inputText, peerName)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"id":        fmt.Sprintf("task-%d", time.Now().UnixMilli()),
				"contextId": fmt.Sprintf("ctx-%d", time.Now().UnixMilli()),
				"status":    map[string]string{"state": "completed"},
				"artifacts": []map[string]any{
					{"parts": []map[string]string{{"type": "text", "text": reply}}},
				},
			},
		})
	}
}

// App holds the demo application state.
type App struct {
	certFile         string
	keyFile          string
	serverCertFile   string
	serverKeyFile    string
	serverCA         string
	backendURL       string
	serverTrustLevel string
	serverListenAddr string
	logHub           *LogHub

	mu        sync.Mutex
	client    *ati.AgentClient
	serverURL string
	level     ati.TrustLevel
	connected bool
	server    *http.Server
}

// restartServerIfNeeded restarts the built-in ATI server if trust level changed.
func (a *App) restartServerIfNeeded(newLevel string) {
	a.mu.Lock()
	oldLevel := a.serverTrustLevel
	if strings.EqualFold(oldLevel, newLevel) {
		a.mu.Unlock()
		return
	}
	a.serverTrustLevel = newLevel
	oldServer := a.server
	a.mu.Unlock()

	slog.Info("[server] restarting with new trust level", "old", oldLevel, "new", newLevel)

	if oldServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		oldServer.Shutdown(ctx)
		cancel()
	}

	go a.startATIServer()
	time.Sleep(200 * time.Millisecond)
}

func (a *App) startATIServer() {
	serverOpts := []ati.ServerOption{
		ati.WithServerCert(a.serverCertFile, a.serverKeyFile),
	}
	if a.serverCA != "" {
		serverOpts = append(serverOpts, ati.WithClientCA(a.serverCA))
	}

	a.mu.Lock()
	trustLevel := a.serverTrustLevel
	a.mu.Unlock()

	switch strings.ToLower(trustLevel) {
	case "pki_only", "pki":
		serverOpts = append(serverOpts, ati.WithClientVerifier(ati.PKIOnly))
	case "badge_required", "badge":
		serverOpts = append(serverOpts, ati.WithClientVerifier(ati.BadgeRequired))
	case "dane_and_badge", "dane":
		serverOpts = append(serverOpts, ati.WithClientVerifier(ati.DANEAndBadge))
	}

	tlsConfig, err := ati.NewServerTLSConfig(serverOpts...)
	if err != nil {
		slog.Error("[server] TLS config failed", "error", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"name":        "ATI Demo Agent",
			"description": "ATI SDK demo agent server",
			"version":     "1.0.0",
			"url":         "https://localhost" + a.serverListenAddr + "/a2a",
			"capabilities": map[string]any{
				"streaming": false,
			},
			"skills": []map[string]string{
				{"id": "chat", "name": "Chat", "description": "AI Agent chat"},
			},
		})
	})

	if a.backendURL != "" {
		mux.HandleFunc("POST /a2a", makeBackendA2AHandler(a.backendURL))
	} else {
		mux.HandleFunc("POST /a2a", makeEchoA2AHandler())
	}

	server := &http.Server{
		Addr:      a.serverListenAddr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	a.mu.Lock()
	a.server = server
	a.mu.Unlock()

	slog.Info("[server] ATI server starting", "addr", a.serverListenAddr, "trustLevel", trustLevel, "backend", a.backendURL)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		slog.Error("[server] ATI server failed", "error", err)
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, _ := staticFS.ReadFile("index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(data)
}

// ConnectRequest is the JSON body for POST /api/connect.
type ConnectRequest struct {
	ServerURL        string `json:"serverUrl"`
	Port             string `json:"port"`
	Version          string `json:"version"`
	ClientTrustLevel string `json:"clientTrustLevel"`
	ServerTrustLevel string `json:"serverTrustLevel"`
}

// ConnectResponse is returned from POST /api/connect.
type ConnectResponse struct {
	Success      bool              `json:"success"`
	Error        string            `json:"error,omitempty"`
	AgentCard    json.RawMessage   `json:"agentCard,omitempty"`
	Verification *VerificationInfo `json:"verification,omitempty"`
}

type VerificationInfo struct {
	ClientSteps      []VerificationStep `json:"clientSteps"`
	ServerSteps      []VerificationStep `json:"serverSteps"`
	Outcome          *OutcomeInfo       `json:"outcome"`
	ServerTrustLevel string             `json:"serverTrustLevel"`
}

type VerificationStep struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

type OutcomeInfo struct {
	DNSDiscovered bool   `json:"dnsDiscovered"`
	CAChainValid  bool   `json:"caChainValid"`
	SANMatches    bool   `json:"sanMatches"`
	BadgeVerified bool   `json:"badgeVerified"`
	DANEVerified  bool   `json:"daneVerified"`
	AchievedLevel string `json:"achievedLevel"`
	PeerATIName   string `json:"peerATIName,omitempty"`
	AgentID       string `json:"agentID,omitempty"`
}

func (a *App) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, ConnectResponse{Error: "invalid request: " + err.Error()})
		return
	}

	// Restart server if trust level changed
	if req.ServerTrustLevel != "" {
		a.restartServerIfNeeded(req.ServerTrustLevel)
	}

	level := parseTrustLevel(req.ClientTrustLevel)
	slog.Info("[demo] connect request", "clientTrustLevel", req.ClientTrustLevel, "parsed", level.String(), "serverTrustLevel", req.ServerTrustLevel, "serverUrl", req.ServerURL, "version", req.Version)

	opts := []ati.AgentClientOption{
		ati.WithTrustLevel(level),
		ati.WithClientTimeout(30 * time.Second),
	}

	if req.Version != "" {
		opts = append(opts, ati.WithTargetVersion(req.Version))
	}

	opts = append(opts, ati.WithIdentityCert(a.certFile, a.keyFile))

	client, err := ati.NewAgentClient(opts...)
	if err != nil {
		writeJSON(w, ConnectResponse{Error: "create client: " + err.Error()})
		return
	}

	serverURL := req.ServerURL
	if req.Port != "" && req.Port != "443" {
		host := strings.TrimPrefix(serverURL, "https://")
		host = strings.Split(host, ":")[0]
		host = strings.TrimSuffix(host, "/")
		serverURL = fmt.Sprintf("https://%s:%s", host, req.Port)
	}

	// Fetch agent card to trigger verification
	slog.Info("connecting to server", "url", serverURL)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp, err := client.Get(ctx, serverURL+"/.well-known/agent.json")
	if err != nil {
		writeJSON(w, ConnectResponse{Error: err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	o := resp.VerificationOutcome
	clientSteps := buildClientSteps(o)
	serverSteps := buildServerSteps(parseTrustLevel(a.serverTrustLevel))
	outcome := &OutcomeInfo{
		DNSDiscovered: o.DNSDiscovered,
		CAChainValid:  o.CAChainValid,
		SANMatches:    o.SANMatches,
		BadgeVerified: o.BadgeVerified,
		DANEVerified:  o.DANEVerified,
		AchievedLevel: o.AchievedLevel.String(),
		PeerATIName:   o.PeerATIName,
		AgentID:       o.AgentID,
	}

	a.mu.Lock()
	a.client = client
	a.serverURL = serverURL
	a.level = level
	a.connected = true
	a.mu.Unlock()

	writeJSON(w, ConnectResponse{
		Success:   true,
		AgentCard: json.RawMessage(body),
		Verification: &VerificationInfo{
			ClientSteps:      clientSteps,
			ServerSteps:      serverSteps,
			Outcome:          outcome,
			ServerTrustLevel: parseTrustLevel(a.serverTrustLevel).String(),
		},
	})
}

func buildClientSteps(o *ati.TrustOutcome) []VerificationStep {
	steps := []VerificationStep{}

	discoveryDetail := fmt.Sprintf("agentId=%s, via aliyun API", o.AgentID)
	steps = append(steps, VerificationStep{
		Name:   "Agent Discovery",
		Pass:   o.DNSDiscovered,
		Detail: discoveryDetail,
	})

	handshakeDetail := fmt.Sprintf("TLS 1.3, CA=%v, SAN=%v", o.CAChainValid, o.SANMatches)
	if o.PeerATIName != "" {
		handshakeDetail += fmt.Sprintf(", peer=%s", o.PeerATIName)
	}
	steps = append(steps, VerificationStep{
		Name:   "mTLS Handshake",
		Pass:   o.CAChainValid && o.SANMatches,
		Detail: handshakeDetail,
	})

	if o.BadgeVerified {
		steps = append(steps, VerificationStep{
			Name:   "Badge Verify",
			Pass:   true,
			Detail: "TLog fingerprint matched",
		})
	} else if o.AchievedLevel >= ati.BadgeRequired {
		steps = append(steps, VerificationStep{
			Name:   "Badge Verify",
			Pass:   false,
			Detail: "badge not verified",
		})
	}

	if o.DANEVerified {
		steps = append(steps, VerificationStep{
			Name:   "DANE/TLSA",
			Pass:   true,
			Detail: "TLSA record matched",
		})
	}

	return steps
}

// buildServerSteps returns inferred server→client verification steps.
// If the connection succeeded, all checks up to the server's trust level passed.
func buildServerSteps(serverLevel ati.TrustLevel) []VerificationStep {
	steps := []VerificationStep{
		{Name: "PKI (CA Chain)", Pass: true, Detail: "client cert accepted by server CA"},
	}

	if serverLevel >= ati.BadgeRequired {
		steps = append(steps, VerificationStep{
			Name:   "Badge Verify",
			Pass:   true,
			Detail: "server verified client badge via TLog",
		})
	}

	if serverLevel >= ati.DANEAndBadge {
		steps = append(steps, VerificationStep{
			Name:   "DANE/TLSA",
			Pass:   true,
			Detail: "server verified client TLSA record",
		})
	}

	return steps
}

// SendRequest is the JSON body for POST /api/send.
type SendRequest struct {
	Message string `json:"message"`
}

// SendResponse is returned from POST /api/send.
type SendResponse struct {
	Success      bool        `json:"success"`
	Error        string      `json:"error,omitempty"`
	TaskID       string      `json:"taskId,omitempty"`
	Status       string      `json:"status,omitempty"`
	Text         string      `json:"text,omitempty"`
	Verification *OutcomeInfo `json:"verification,omitempty"`
}

type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type sendMessageParams struct {
	Message   a2aMessage `json:"message"`
	ContextID string     `json:"contextId,omitempty"`
}

type a2aMessage struct {
	Role  string    `json:"role"`
	Parts []a2aPart `json:"parts"`
}

type a2aPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

var (
	reqID     int
	contextID string
)

func (a *App) handleSend(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	client := a.client
	serverURL := a.serverURL
	connected := a.connected
	a.mu.Unlock()

	if !connected || client == nil {
		writeJSON(w, SendResponse{Error: "not connected"})
		return
	}

	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, SendResponse{Error: "invalid request"})
		return
	}

	reqID++
	rpcReq := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  "message/send",
		Params: sendMessageParams{
			Message: a2aMessage{
				Role:  "user",
				Parts: []a2aPart{{Type: "text", Text: req.Message}},
			},
			ContextID: contextID,
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	resp, err := client.Post(ctx, serverURL+"/a2a", rpcReq)
	if err != nil {
		writeJSON(w, SendResponse{Error: err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	o := resp.VerificationOutcome
	verification := &OutcomeInfo{
		DNSDiscovered: o.DNSDiscovered,
		CAChainValid:  o.CAChainValid,
		SANMatches:    o.SANMatches,
		BadgeVerified: o.BadgeVerified,
		DANEVerified:  o.DANEVerified,
		AchievedLevel: o.AchievedLevel.String(),
		PeerATIName:   o.PeerATIName,
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		writeJSON(w, SendResponse{Error: "invalid response: " + string(body), Verification: verification})
		return
	}
	if rpcResp.Error != nil {
		writeJSON(w, SendResponse{
			Error:        fmt.Sprintf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message),
			Verification: verification,
		})
		return
	}

	var task struct {
		ID        string `json:"id"`
		ContextID string `json:"contextId"`
		Status    struct {
			State string `json:"state"`
		} `json:"status"`
		Artifacts []struct {
			Parts []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"artifacts"`
	}
	json.Unmarshal(rpcResp.Result, &task)

	if task.ContextID != "" {
		contextID = task.ContextID
	} else if task.ID != "" {
		contextID = task.ID
	}

	var text strings.Builder
	for _, a := range task.Artifacts {
		for _, p := range a.Parts {
			if p.Text != "" {
				text.WriteString(p.Text)
			}
		}
	}

	writeJSON(w, SendResponse{
		Success:      true,
		TaskID:       task.ID,
		Status:       task.Status.State,
		Text:         text.String(),
		Verification: verification,
	})
}

func (a *App) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.client = nil
	a.connected = false
	a.serverURL = ""
	reqID = 0
	contextID = ""
	a.mu.Unlock()

	writeJSON(w, map[string]bool{"success": true})
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	connected := a.connected
	serverURL := a.serverURL
	level := a.level
	a.mu.Unlock()

	writeJSON(w, map[string]any{
		"connected":        connected,
		"serverUrl":        serverURL,
		"clientTrustLevel": level.String(),
		"serverTrustLevel": parseTrustLevel(a.serverTrustLevel).String(),
		"serverAddr":       a.serverListenAddr,
	})
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := a.logHub.Subscribe()
	defer a.logHub.Unsubscribe(ch)

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// LogHub captures slog records and fans them out to SSE subscribers.
type LogHub struct {
	mu          sync.RWMutex
	subscribers map[chan string]struct{}
}

func newLogHub() *LogHub {
	return &LogHub{
		subscribers: make(map[chan string]struct{}),
	}
}

func (h *LogHub) Subscribe() chan string {
	ch := make(chan string, 100)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *LogHub) Unsubscribe(ch chan string) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	close(ch)
	h.mu.Unlock()
}

func (h *LogHub) broadcast(msg string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

// slog.Handler implementation
func (h *LogHub) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *LogHub) Handle(_ context.Context, record slog.Record) error {
	var sb strings.Builder
	sb.WriteString(record.Time.Format("15:04:05"))
	sb.WriteString(" ")
	sb.WriteString(record.Level.String())
	sb.WriteString(" ")
	sb.WriteString(record.Message)
	record.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(fmt.Sprintf("%v", a.Value.Any()))
		return true
	})
	line := sb.String()
	h.broadcast(line)
	fmt.Fprintln(os.Stderr, line)
	return nil
}

func (h *LogHub) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *LogHub) WithGroup(_ string) slog.Handler      { return h }
