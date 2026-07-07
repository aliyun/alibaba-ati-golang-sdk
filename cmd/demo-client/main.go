// Command demo-client runs the ATI demo client web UI (Agent A) as a standalone
// process. The client logic and embedded web assets live in
// internal/demo/client.
package main

import (
	"flag"
	"log"
	"os"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/demo/client"
)

func main() {
	var (
		listenAddr   = flag.String("listen", ":7080", "web UI listen address")
		certFile     = flag.String("cert", "cert/identity-www.ats-client.asia.pem", "client identity certificate PEM")
		keyFile      = flag.String("key", "cert/identity-www.ats-client.asia.key.pem", "client private key PEM")
		clientHost   = flag.String("client-host", "www.ats-client.asia", "client agent hostname for the first identity")
		certFile2    = flag.String("cert2", "cert/identity-ats-client.asia.pem", "second client identity certificate PEM")
		keyFile2     = flag.String("key2", "cert/identity-ats-client.asia.key.pem", "second client private key PEM")
		clientHost2  = flag.String("client-host2", "ats-client.asia", "client agent hostname for the second identity")
		proxyPort    = flag.String("proxy-port", "7443", "proxy mTLS port")
		proxyAPIAddr = flag.String("proxy-api", "http://localhost:7444", "proxy plain HTTP API base URL (status/policy)")
		dashKeyFlag  = flag.String("dashscope-key", "", "DashScope API key (or set DASHSCOPE_API_KEY env)")
		dashModelF   = flag.String("dashscope-model", "", "DashScope model (or set DASHSCOPE_MODEL_NAME env, default qwen-plus)")
	)
	flag.Parse()

	dashKey := *dashKeyFlag
	if dashKey == "" {
		dashKey = os.Getenv("DASHSCOPE_API_KEY")
	}
	dashModel := *dashModelF
	if dashModel == "" {
		dashModel = os.Getenv("DASHSCOPE_MODEL_NAME")
	}

	if err := client.Run(client.Config{
		ListenAddr:   *listenAddr,
		Cert:         *certFile,
		Key:          *keyFile,
		ClientHost:   *clientHost,
		Cert2:        *certFile2,
		Key2:         *keyFile2,
		ClientHost2:  *clientHost2,
		ProxyPort:    *proxyPort,
		ProxyAPIAddr: *proxyAPIAddr,
		DashKey:      dashKey,
		DashModel:    dashModel,
	}); err != nil {
		log.Fatal(err)
	}
}
