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
	return parseClientFlagsFromArgs(flag.CommandLine, nil)
}

func parseClientFlagsFromArgs(fs *flag.FlagSet, args []string) *clientConfig {
	cfg := &clientConfig{}
	fs.StringVar(&cfg.certFile, "cert", "client.crt", "Client identity certificate (self-signed with ati:// URI SAN)")
	fs.StringVar(&cfg.keyFile, "key", "client.key", "Client identity private key")
	fs.StringVar(&cfg.serverURL, "url", "https://dns-test.aliyuncs.com:8443/hello", "Server URL to connect to")
	fs.StringVar(&cfg.trustLevel, "trust", "badge", "Trust level: pki_only, badge, dane")
	fs.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "Request timeout")
	if args != nil {
		fs.Parse(args)
	} else {
		fs.Parse(nil)
	}
	return cfg
}

func buildClientOptions(cfg *clientConfig) []ati.AgentClientOption {
	opts := []ati.AgentClientOption{
		ati.WithIdentityCert(cfg.certFile, cfg.keyFile),
		ati.WithClientTimeout(cfg.timeout),
	}

	switch cfg.trustLevel {
	case "none":
		opts = append(opts, ati.WithTrustLevel(ati.PolicyNone))
	case "pki_only", "pki":
		opts = append(opts, ati.WithTrustLevel(ati.PKIOnly))
	case "badge_required", "badge":
		opts = append(opts, ati.WithTrustLevel(ati.BadgeRequired))
	case "dane_and_badge", "dane":
		opts = append(opts, ati.WithTrustLevel(ati.DANEAndBadge))
	default:
		log.Fatalf("unknown trust level: %s (use none/pki_only/badge/dane)", cfg.trustLevel)
	}

	return opts
}

func formatCertStatus(status ati.CertStatus) string {
	return fmt.Sprintf("Identity cert expires: %s (in %d days)", status.ExpiresAt.Format("2006-01-02"), status.DaysRemaining)
}

func formatResponse(status string, body []byte) string {
	return fmt.Sprintf("Status: %s\nBody:   %s", status, string(body))
}

func formatVerificationOutcome(o *ati.TrustOutcome) string {
	if o == nil {
		return ""
	}
	result := fmt.Sprintf("DNS Discovered:  %v\n", o.DNSDiscovered)
	result += fmt.Sprintf("CA Chain Valid:  %v\n", o.CAChainValid)
	result += fmt.Sprintf("SAN Matches:     %v\n", o.SANMatches)
	result += fmt.Sprintf("Badge Verified:  %v\n", o.BadgeVerified)
	result += fmt.Sprintf("DANE Verified:   %v\n", o.DANEVerified)
	result += fmt.Sprintf("Achieved Level:  %s\n", o.AchievedLevel)
	if o.RequestedLevel != nil {
		result += fmt.Sprintf("Requested Level: %s\n", o.RequestedLevel)
	}
	if o.PeerATIName != "" {
		result += fmt.Sprintf("Peer ATI Name:   %s\n", o.PeerATIName)
	}
	if o.AgentID != "" {
		result += fmt.Sprintf("Agent ID:        %s\n", o.AgentID)
	}
	return result
}

func runClient(cfg *clientConfig) error {
	opts := buildClientOptions(cfg)

	client, err := ati.NewAgentClient(opts...)
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}

	status := client.CertStatus()
	fmt.Println(formatCertStatus(status))
	if status.IsExpired {
		return fmt.Errorf("identity certificate is expired")
	}

	ctx := context.Background()
	fmt.Printf("\nConnecting to %s ...\n", cfg.serverURL)

	resp, err := client.Get(ctx, cfg.serverURL)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	fmt.Printf("\n=== Response ===\n")
	fmt.Println(formatResponse(resp.Status, body))

	if resp.VerificationOutcome != nil {
		fmt.Printf("\n=== Trust Verification ===\n")
		fmt.Print(formatVerificationOutcome(resp.VerificationOutcome))
	}

	return nil
}

func main() {
	cfg := parseClientFlags()
	if err := runClient(cfg); err != nil {
		log.Fatal(err)
	}
}
