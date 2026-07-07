package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/a2a"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/backend"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/mcp"
)

func main() {
	var (
		listenAddr = flag.String("listen", ":8443", "proxy listen address")
		backendURL = flag.String("backend", "https://dns-ai-platform.aliyun-inc.com/v1/agent-messages", "backend agent URL")
		serverCert = flag.String("server-cert", "", "server certificate PEM file")
		serverKey  = flag.String("server-key", "", "server private key PEM file")
		caBundle   = flag.String("ca-bundle", "", "CA bundle for verifying client identity certs (optional)")
		trustLevel = flag.String("trust-level", "pki_only", "client verification level: pki_only, badge, dane")

		agentName    = flag.String("agent-name", "ATI Agent", "agent name for A2A agent card")
		agentDesc    = flag.String("agent-desc", "ATI-secured AI agent", "agent description")
		agentURL     = flag.String("agent-url", "", "public-facing URL of this proxy (for agent card)")
		agentVersion = flag.String("agent-version", "1.0.0", "agent version")
	)
	flag.Parse()

	token := os.Getenv("BACKEND_TOKEN")
	if token == "" {
		log.Fatal("BACKEND_TOKEN environment variable is required")
	}

	if *serverCert == "" || *serverKey == "" {
		flag.Usage()
		log.Fatal("--server-cert and --server-key are required")
	}

	// ATI mTLS server config
	serverOpts := []ati.ServerOption{
		ati.WithServerCert(*serverCert, *serverKey),
	}
	if *caBundle != "" {
		serverOpts = append(serverOpts, ati.WithClientCA(*caBundle))
	}

	// Trust level configuration
	switch *trustLevel {
	case "pki_only", "pki", "none":
		serverOpts = append(serverOpts, ati.WithClientVerifier(ati.PKIOnly))
		log.Println("Trust level: PKI_ONLY (cert validity only)")
	case "badge_required", "badge":
		serverOpts = append(serverOpts, ati.WithClientVerifier(ati.BadgeRequired))
		log.Println("Trust level: BADGE_REQUIRED (cert + TL fingerprint)")
	case "dane_and_badge", "dane", "full":
		serverOpts = append(serverOpts, ati.WithClientVerifier(ati.DANEAndBadge))
		log.Println("Trust level: DANE_AND_BADGE (cert + Badge + DANE)")
	default:
		log.Fatalf("unknown trust level %q: use pki_only, badge, or dane", *trustLevel)
	}

	tlsConfig, err := ati.NewServerTLSConfig(serverOpts...)
	if err != nil {
		log.Fatalf("ATI TLS config error: %v", err)
	}

	// Shared backend client
	bc := backend.NewClient(*backendURL, token)

	// A2A handler
	taskStore := a2a.NewTaskStore(time.Hour)
	a2aHandler := &a2a.Handler{Store: taskStore, Backend: bc}

	agentCardURL := *agentURL
	if agentCardURL == "" {
		agentCardURL = fmt.Sprintf("https://localhost%s", *listenAddr)
	}
	agentCardHandler := a2a.NewAgentCardHandler(a2a.AgentCardConfig{
		Name:        *agentName,
		Description: *agentDesc,
		URL:         agentCardURL + "/a2a",
		Version:     *agentVersion,
	})

	// MCP handler
	sessionStore := mcp.NewSessionStore(30 * time.Minute)
	mcpHandler := mcp.NewHandler(sessionStore, bc, mcp.EntityInfo{
		Name:    *agentName,
		Version: *agentVersion,
	})

	// Router
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent.json", agentCardHandler)
	mux.Handle("POST /a2a", a2aHandler)
	mux.Handle("POST /mcp", mcpHandler)
	mux.Handle("GET /mcp", mcpHandler)
	mux.Handle("DELETE /mcp", mcpHandler)
	mux.HandleFunc("POST /", legacyHandler(bc))

	server := &http.Server{
		Addr:      *listenAddr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Printf("ATI proxy listening on %s", *listenAddr)
	log.Printf("  A2A:    POST /a2a | GET /.well-known/agent.json")
	log.Printf("  MCP:    POST|GET /mcp")
	log.Printf("  Legacy: POST /")
	log.Printf("  Backend: %s", *backendURL)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func legacyHandler(bc *backend.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerCert := r.TLS.PeerCertificates[0]
			for _, uri := range peerCert.URIs {
				if uri.String() != "" {
					log.Printf("[Legacy] request from: %s", uri.String())
					break
				}
			}
		}

		// Parse incoming request body as backend request
		var backendReq backend.AgentRequest
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > 0 {
			if jsonErr := json.Unmarshal(body, &backendReq); jsonErr != nil {
				http.Error(w, "invalid json: "+jsonErr.Error(), http.StatusBadRequest)
				return
			}
		}
		if backendReq.ResponseMode == "" {
			backendReq.ResponseMode = "streaming"
		}

		events, errc := bc.CallStream(r.Context(), &backendReq)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		for evt := range events {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, evt.Data)
			flusher.Flush()
		}

		if err := <-errc; err != nil {
			log.Printf("[Legacy] stream error: %v", err)
		}
	}
}
