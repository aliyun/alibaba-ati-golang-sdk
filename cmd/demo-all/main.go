// Command demo-all runs the full ATI demo — the weather agent backend (Agent B),
// the mTLS termination proxy, and the client web UI (Agent A) — inside a single
// process. Each component still listens on its own localhost port and the three
// talk over the loopback exactly as they do when run separately, so the mutual
// mTLS verification is genuine; only the process count changes.
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/demo/backend"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/demo/client"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/demo/proxy"
)

func main() {
	var (
		certDir    = flag.String("cert-dir", "cert", "directory holding the demo certificates")
		serverCert = flag.String("server-cert", "", "proxy server cert PEM (default <cert-dir>/ats-server.asia.pem)")
		serverKey  = flag.String("server-key", "", "proxy server key PEM (default <cert-dir>/ats-server.asia.key)")
		caBundle   = flag.String("ca-bundle", "", "client CA bundle (default <cert-dir>/idca-chain.crt)")
		clientCert  = flag.String("client-cert", "", "first client identity cert PEM (default <cert-dir>/identity-www.ats-client.asia.pem)")
		clientKey   = flag.String("client-key", "", "first client identity key PEM (default <cert-dir>/identity-www.ats-client.asia.key.pem)")
		clientCert2 = flag.String("client-cert2", "", "second client identity cert PEM (default <cert-dir>/identity-ats-client.asia.pem)")
		clientKey2  = flag.String("client-key2", "", "second client identity key PEM (default <cert-dir>/identity-ats-client.asia.key.pem)")

		webAddr     = flag.String("web-listen", ":7080", "client web UI listen address")
		proxyAddr   = flag.String("proxy-listen", ":7443", "proxy mTLS listen address")
		proxyAPI    = flag.String("proxy-api-listen", ":7444", "proxy plain HTTP API listen address")
		backendAddr = flag.String("backend-listen", ":7100", "backend weather agent listen address")
		trustLevel  = flag.String("trust", "pki_only", "server-side client verification level: pki_only, badge, dane")

		dashKeyFlag = flag.String("dashscope-key", "", "DashScope API key (or set DASHSCOPE_API_KEY env)")
		dashModelF  = flag.String("dashscope-model", "", "DashScope model (or set DASHSCOPE_MODEL_NAME env, default qwen-plus)")
	)
	flag.Parse()

	def := func(v, name string) string {
		if v != "" {
			return v
		}
		return filepath.Join(*certDir, name)
	}
	sCert := def(*serverCert, "ats-server.asia.pem")
	sKey := def(*serverKey, "ats-server.asia.key")
	ca := def(*caBundle, "idca-chain.crt")
	cCert := def(*clientCert, "identity-www.ats-client.asia.pem")
	cKey := def(*clientKey, "identity-www.ats-client.asia.key.pem")
	cCert2 := def(*clientCert2, "identity-ats-client.asia.pem")
	cKey2 := def(*clientKey2, "identity-ats-client.asia.key.pem")

	dashKey := *dashKeyFlag
	if dashKey == "" {
		dashKey = os.Getenv("DASHSCOPE_API_KEY")
	}
	dashModel := *dashModelF
	if dashModel == "" {
		dashModel = os.Getenv("DASHSCOPE_MODEL_NAME")
	}

	// Backend weather agent (Agent B).
	go func() {
		if err := backend.Run(backend.Config{
			ListenAddr: *backendAddr,
			DashKey:    dashKey,
			DashModel:  dashModel,
		}); err != nil {
			log.Fatalf("[demo-all] backend exited: %v", err)
		}
	}()

	// mTLS termination proxy fronting the backend.
	go func() {
		if err := proxy.Run(proxy.Config{
			ListenAddr:    *proxyAddr,
			APIListenAddr: *proxyAPI,
			CertFile:      sCert,
			KeyFile:       sKey,
			CABundle:      ca,
			TrustLevel:    *trustLevel,
			BackendURL:    "http://localhost" + *backendAddr,
		}); err != nil {
			log.Fatalf("[demo-all] proxy exited: %v", err)
		}
	}()

	// Client web UI (Agent A) — blocks in the main goroutine.
	proxyPort := *proxyAddr
	if len(proxyPort) > 0 && proxyPort[0] == ':' {
		proxyPort = proxyPort[1:]
	}
	if err := client.Run(client.Config{
		ListenAddr:   *webAddr,
		Cert:         cCert,
		Key:          cKey,
		ClientHost:   "www.ats-client.asia",
		Cert2:        cCert2,
		Key2:         cKey2,
		ClientHost2:  "ats-client.asia",
		ProxyPort:    proxyPort,
		ProxyAPIAddr: "http://localhost" + *proxyAPI,
		DashKey:      dashKey,
		DashModel:    dashModel,
	}); err != nil {
		log.Fatalf("[demo-all] client exited: %v", err)
	}
}
