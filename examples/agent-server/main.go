//nolint:forbidigo,gosec // Example program
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/aliyun/alibaba-ati-golang-sdk/ati"
)

type serverConfig struct {
	certFile   string
	keyFile    string
	caBundle   string
	addr       string
	trustLevel string
}

func parseServerFlags() *serverConfig {
	return parseServerFlagsFromArgs(flag.CommandLine, nil)
}

func parseServerFlagsFromArgs(fs *flag.FlagSet, args []string) *serverConfig {
	cfg := &serverConfig{}
	fs.StringVar(&cfg.certFile, "cert", "server.crt", "Server TLS certificate (public CA signed)")
	fs.StringVar(&cfg.keyFile, "key", "server.key", "Server TLS private key")
	fs.StringVar(&cfg.caBundle, "ca", "", "Optional CA bundle for client cert verification (empty = accept self-signed)")
	fs.StringVar(&cfg.addr, "addr", ":8443", "Listen address")
	fs.StringVar(&cfg.trustLevel, "trust", "pki_only", "Trust level: none, pki_only, badge, dane")
	if args != nil {
		fs.Parse(args)
	} else {
		fs.Parse(nil)
	}
	return cfg
}

func buildServerOptions(cfg *serverConfig) []ati.ServerOption {
	opts := []ati.ServerOption{
		ati.WithServerCert(cfg.certFile, cfg.keyFile),
	}

	if cfg.caBundle != "" {
		opts = append(opts, ati.WithClientCA(cfg.caBundle))
	}

	switch cfg.trustLevel {
	case "none":
		opts = append(opts, ati.WithClientVerifier(ati.PolicyNone))
	case "pki_only", "pki":
		opts = append(opts, ati.WithClientVerifier(ati.PKIOnly))
	case "badge_required", "badge":
		opts = append(opts, ati.WithClientVerifier(ati.BadgeRequired))
	case "dane_and_badge", "dane":
		opts = append(opts, ati.WithClientVerifier(ati.DANEAndBadge))
	default:
		log.Fatalf("unknown trust level: %s (use none/pki_only/badge/dane)", cfg.trustLevel)
	}

	return opts
}

func buildMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		peerName, err := ati.PeerATIName(r.TLS)
		resp := map[string]any{
			"message": "Hello from ATI agent server",
			"method":  r.Method,
		}
		if err == nil {
			resp["peer_ati_name"] = peerName.Raw
			resp["peer_host"] = peerName.Host
			resp["peer_version"] = peerName.Version
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil {
			json.NewDecoder(r.Body).Decode(&body)
		}
		resp := map[string]any{
			"echo": body,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return mux
}

func formatServerStartup(cfg *serverConfig) string {
	return fmt.Sprintf("ATI Agent Server starting on %s\n  Trust level: %s\n  Cert: %s\n  Endpoints: /hello, /echo",
		cfg.addr, cfg.trustLevel, cfg.certFile)
}

func runServer(cfg *serverConfig) error {
	opts := buildServerOptions(cfg)

	tlsConfig, err := ati.NewServerTLSConfig(opts...)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	mux := buildMux()

	server := &http.Server{
		Addr:      cfg.addr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	fmt.Println(formatServerStartup(cfg))

	// TLS cert/key already loaded in tlsConfig, pass empty strings to ListenAndServeTLS
	if err := server.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

func main() {
	cfg := parseServerFlags()
	if err := runServer(cfg); err != nil {
		log.Fatal(err)
	}
}
