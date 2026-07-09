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

func main() {
	certFile := flag.String("cert", "server.crt", "Server TLS certificate (public CA signed)")
	keyFile := flag.String("key", "server.key", "Server TLS private key")
	caBundle := flag.String("ca", "", "Optional CA bundle for client cert verification (empty = accept self-signed)")
	addr := flag.String("addr", ":8443", "Listen address")
	trustLevel := flag.String("trust", "pki_only", "Trust level: pki_only, badge, dane")
	flag.Parse()

	opts := []ati.ServerOption{
		ati.WithServerCert(*certFile, *keyFile),
	}

	if *caBundle != "" {
		opts = append(opts, ati.WithClientCA(*caBundle))
	}

	switch *trustLevel {
	case "pki_only", "pki", "none":
		opts = append(opts, ati.WithClientVerifier(ati.PKIOnly))
	case "badge_required", "badge":
		opts = append(opts, ati.WithClientVerifier(ati.BadgeRequired))
	case "dane_and_badge", "dane":
		opts = append(opts, ati.WithClientVerifier(ati.DANEAndBadge))
	default:
		log.Fatalf("unknown trust level: %s (use pki_only/badge/dane)", *trustLevel)
	}

	tlsConfig, err := ati.NewServerTLSConfig(opts...)
	if err != nil {
		log.Fatalf("Failed to create TLS config: %v", err)
	}

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

	server := &http.Server{
		Addr:      *addr,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	fmt.Printf("ATI Agent Server starting on %s\n", *addr)
	fmt.Printf("  Trust level: %s\n", *trustLevel)
	fmt.Printf("  Cert: %s\n", *certFile)
	fmt.Printf("  Endpoints: /hello, /echo\n")

	// TLS cert/key already loaded in tlsConfig, pass empty strings to ListenAndServeTLS
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
