// Command demo-proxy runs the ATI demo mTLS termination proxy as a standalone
// process. The proxy logic lives in internal/demo/proxy.
package main

import (
	"flag"
	"log"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/demo/proxy"
)

func main() {
	var (
		listenAddr    = flag.String("listen", ":7443", "mTLS proxy listen address")
		apiListenAddr = flag.String("api-listen", ":7444", "plain HTTP API listen address (status, policy)")
		certFile      = flag.String("cert", "", "server TLS certificate PEM")
		keyFile       = flag.String("key", "", "server TLS private key PEM")
		caBundle      = flag.String("ca-bundle", "", "CA bundle for verifying client certs")
		trustLevel    = flag.String("trust", "pki_only", "client verification level: pki_only, badge, dane")
		backendURL    = flag.String("backend", "http://localhost:9100", "backend agent URL (weather agent: /chat, MCP: /mcp)")
	)
	flag.Parse()

	if err := proxy.Run(proxy.Config{
		ListenAddr:    *listenAddr,
		APIListenAddr: *apiListenAddr,
		CertFile:      *certFile,
		KeyFile:       *keyFile,
		CABundle:      *caBundle,
		TrustLevel:    *trustLevel,
		BackendURL:    *backendURL,
	}); err != nil {
		log.Fatal(err)
	}
}
