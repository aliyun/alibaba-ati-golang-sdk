//nolint:forbidigo,gosec // Example program
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/ati"
)

func main() {
	certFile := flag.String("cert", "client.crt", "Client identity certificate (self-signed with ati:// URI SAN)")
	keyFile := flag.String("key", "client.key", "Client identity private key")
	serverURL := flag.String("url", "https://dns-test.aliyuncs.com:8443/hello", "Server URL to connect to")
	trustLevel := flag.String("trust", "badge", "Trust level: pki_only, badge, dane")
	timeout := flag.Duration("timeout", 10*time.Second, "Request timeout")
	flag.Parse()

	opts := []ati.AgentClientOption{
		ati.WithIdentityCert(*certFile, *keyFile),
		ati.WithClientTimeout(*timeout),
	}

	switch *trustLevel {
	case "pki_only", "pki":
		opts = append(opts, ati.WithTrustLevel(ati.PKIOnly))
	case "badge_required", "badge":
		opts = append(opts, ati.WithTrustLevel(ati.BadgeRequired))
	case "dane_and_badge", "dane":
		opts = append(opts, ati.WithTrustLevel(ati.DANEAndBadge))
	default:
		log.Fatalf("unknown trust level: %s (use pki_only/badge/dane)", *trustLevel)
	}

	client, err := ati.NewAgentClient(opts...)
	if err != nil {
		log.Fatalf("Failed to create agent client: %v", err)
	}

	// Check cert status
	status := client.CertStatus()
	fmt.Printf("Identity cert expires: %s (in %d days)\n", status.ExpiresAt.Format("2006-01-02"), status.DaysRemaining)
	if status.IsExpired {
		log.Fatal("Identity certificate is expired!")
	}

	// Make request
	ctx := context.Background()
	fmt.Printf("\nConnecting to %s ...\n", *serverURL)

	resp, err := client.Get(ctx, *serverURL)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	fmt.Printf("\n=== Response ===\n")
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body:   %s\n", string(body))

	if resp.VerificationOutcome != nil {
		o := resp.VerificationOutcome
		fmt.Printf("\n=== Trust Verification ===\n")
		fmt.Printf("DNS Discovered:  %v\n", o.DNSDiscovered)
		fmt.Printf("CA Chain Valid:  %v\n", o.CAChainValid)
		fmt.Printf("SAN Matches:     %v\n", o.SANMatches)
		fmt.Printf("Badge Verified:  %v\n", o.BadgeVerified)
		fmt.Printf("DANE Verified:   %v\n", o.DANEVerified)
		fmt.Printf("Achieved Level:  %s\n", o.AchievedLevel)
		if o.RequestedLevel != nil {
			fmt.Printf("Requested Level: %s\n", o.RequestedLevel)
		}
		if o.PeerATIName != "" {
			fmt.Printf("Peer ATI Name:   %s\n", o.PeerATIName)
		}
		if o.AgentID != "" {
			fmt.Printf("Agent ID:        %s\n", o.AgentID)
		}
	}
}
