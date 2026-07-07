// Command dane-check diagnoses server-side client DANE verification without
// needing dig/nslookup on the host. It reuses the exact SDK code path the
// server uses: StandardDANEResolver (local DNSSEC chain validation) +
// DANEVerifier.VerifyIdentity, so its result matches what the proxy sees.
//
// Usage:
//
//	dane-check -cert cert/identity-www.ats-client.asia.pem
//	dane-check -cert <pem> -host www.ats-client.asia -dns 8.8.8.8:53
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/models"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/verify"
)

func main() {
	var (
		certPath = flag.String("cert", "", "client identity certificate PEM (required)")
		hostFlag = flag.String("host", "", "override host for TLSA lookup (default: from cert ati:// URI SAN)")
		dnsFlag  = flag.String("dns", "", "DNS server addr host:port (default: 8.8.8.8:53)")
		timeout  = flag.Duration("timeout", 5*time.Second, "DNS lookup timeout")
	)
	flag.Parse()

	if *certPath == "" {
		fmt.Fprintln(os.Stderr, "error: -cert is required")
		flag.Usage()
		os.Exit(2)
	}

	pemBytes, err := os.ReadFile(*certPath)
	if err != nil {
		fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		fatalf("no PEM block found in %s", *certPath)
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fatalf("parse certificate: %v", err)
	}

	certID := verify.CertIdentityFromX509(x509Cert)

	host := *hostFlag
	if host == "" {
		atiName := certID.ATIName()
		if atiName == nil {
			fatalf("cert has no ati:// URI SAN; pass -host explicitly")
		}
		host = atiName.Host
	}

	fqdn, err := models.NewFqdn(host)
	if err != nil {
		fatalf("invalid host %q: %v", host, err)
	}

	fmt.Println("=== dane-check ===")
	fmt.Printf("cert file           : %s\n", *certPath)
	fmt.Printf("cert subject        : %s\n", x509Cert.Subject)
	fmt.Printf("DANE host           : %s\n", host)
	fmt.Printf("TLSA query name     : %s\n", fqdn.IdentityTLSAName())
	fmt.Printf("cert full  SHA-256  : %s  (Selector=0)\n", certID.Fingerprint.ToHex())
	fmt.Printf("cert SPKI  SHA-256  : %s  (Selector=1)\n", certID.SPKIFingerprint.ToHex())

	var opts []verify.DANEResolverOption
	if *dnsFlag != "" {
		opts = append(opts, verify.WithDANEServer(*dnsFlag))
	}
	opts = append(opts, verify.WithDANETimeout(*timeout))
	resolver := verify.NewStandardDANEResolver(opts...)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+2*time.Second)
	defer cancel()

	// Step 1: raw TLSA lookup (records + DNSSEC status).
	fmt.Println("\n--- Step ②③④: TLSA lookup + DNSSEC chain ---")
	lookup, lookupErr := resolver.LookupIdentityTLSA(ctx, fqdn)
	if lookupErr != nil {
		fmt.Printf("lookup error        : %v\n", lookupErr)
	}
	fmt.Printf("records found       : %v\n", lookup.Found)
	fmt.Printf("DNSSEC valid        : %v\n", lookup.DNSSECValid)
	for i, rec := range lookup.Records {
		fmt.Printf("  TLSA[%d]           : usage=%d selector=%d matchingType=%d hash=%s\n",
			i, rec.Usage, rec.Selector, rec.MatchingType, rec.CertHash)
	}

	// Step 2: full identity verification (same call the server makes).
	fmt.Println("\n--- Step ⑤: VerifyIdentity (server 端相同调用) ---")
	outcome := verify.NewDANEVerifier(resolver).VerifyIdentity(ctx, fqdn, certID)
	fmt.Printf("outcome type        : %s\n", outcome.Type.String())
	fmt.Printf("cert hash used      : %s\n", outcome.CertHashUsed)
	fmt.Printf("PASS (IsPass)       : %v\n", outcome.IsPass())
	if outcome.Error != nil {
		fmt.Printf("error               : %v\n", outcome.Error)
	}

	fmt.Println()
	if outcome.IsPass() {
		fmt.Println("RESULT: DANE 通过 ✅")
		return
	}
	fmt.Printf("RESULT: DANE 失败 ❌ (%s)\n", outcome.Type.String())
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
