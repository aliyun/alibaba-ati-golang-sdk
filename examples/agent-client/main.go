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

type clientConfig struct {
	certFile   string
	keyFile    string
	serverURL  string
	trustLevel string
	timeout    time.Duration
}

func parseClientFlags() *clientConfig {
	cfg := &clientConfig{}
	cfg.certFile = *flag.String("cert", "client.crt", "Client identity certificate (self-signed with ati:// URI SAN)")
	cfg.keyFile = *flag.String("key", "client.key", "Client identity private key")
	cfg.serverURL = *flag.String("url", "https://dns-test.aliyuncs.com:8443/hello", "Server URL to connect to")
	cfg.trustLevel = *flag.String("trust", "badge", "Trust level: pki_only, badge, dane")
	cfg.timeout = *flag.Duration("timeout", 10*time.Second, "Request timeout")
	flag.Parse()
	return cfg
}

func buildClientOptions(cfg *clientConfig) []ati.AgentClientOption {
	opts := []ati.AgentClientOption{
		ati.WithIdentityCert(cfg.certFile, cfg.keyFile),
		ati.WithClientTimeout(cfg.timeout),
	}

	switch cfg.trustLevel {
	case "pki_only", "pki":
		opts = append(opts, ati.WithTrustLevel(ati.PKIOnly))
	case "badge_required", "badge":
		opts = append(opts, ati.WithTrustLevel(ati.BadgeRequired))
	case "dane_and_badge", "dane":
		opts = append(opts, ati.WithTrustLevel(ati.DANEAndBadge))
	default:
		log.Fatalf("unknown trust level: %s (use pki_only/badge/dane)", cfg.trustLevel)
	}

	return opts
}

func runClient(cfg *clientConfig) error {
	opts := buildClientOptions(cfg)

	client, err := ati.NewAgentClient(opts...)
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	// Check cert status
	status := client.CertStatus()
	fmt.Printf("Identity cert expires: %s (in %d days)\n", status.ExpiresAt.Format("2006-01-02"), status.DaysRemaining)
	if status.IsExpired {
		return fmt.Errorf("identity certificate is expired")
	}

	// Make request
	ctx := context.Background()
	fmt.Printf("\nConnecting to %s ...\n", cfg.serverURL)

	resp, err := client.Get(ctx, cfg.serverURL)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
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

	return nil
}

func main() {
	cfg := parseClientFlags()
	if err := runClient(cfg); err != nil {
		log.Fatal(err)
	}
}
