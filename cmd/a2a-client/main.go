package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/ati"
)

func main() {
	var (
		serverURL  = flag.String("server", "https://ats-client.asia", "server URL")
		certFile   = flag.String("cert", "", "client identity certificate PEM")
		keyFile    = flag.String("key", "", "client private key PEM")
		caBundle   = flag.String("ca-bundle", "", "CA bundle for verifying server cert (optional, uses system CA if omitted)")
		trustLevel = flag.String("trust-level", "badge", "trust level: pki_only, badge, dane")
	)
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("--cert and --key are required")
	}

	level := parseTrustLevel(*trustLevel)
	client := buildClient(*certFile, *keyFile, *caBundle, level)

	// Step 1: Verify server by fetching agent card
	fmt.Printf("=== Server Verification (trust-level: %s) ===\n", *trustLevel)
	fmt.Printf("Target: %s\n\n", *serverURL)

	fmt.Println("--- Fetching Agent Card ---")
	ok := fetchAgentCard(client, *serverURL+"/.well-known/agent.json")
	if !ok {
		os.Exit(1)
	}

	// Step 2: Interactive A2A chat
	fmt.Printf("\n=== A2A Chat (type 'quit' to exit) ===\n")
	a2aChat(client, *serverURL+"/a2a")
}

func parseTrustLevel(s string) ati.TrustLevel {
	switch strings.ToLower(s) {
	case "pki_only", "pki", "none":
		return ati.PKIOnly
	case "badge_required", "badge":
		return ati.BadgeRequired
	case "dane_and_badge", "dane", "full":
		return ati.DANEAndBadge
	default:
		log.Fatalf("unknown trust level %q: use pki_only, badge, or dane", s)
		return ati.BadgeRequired
	}
}

func buildClient(certFile, keyFile, caBundle string, level ati.TrustLevel) *ati.AgentClient {
	opts := []ati.AgentClientOption{
		ati.WithTrustLevel(level),
	}

	if caBundle != "" {
		opts = append(opts, ati.WithMTLSCerts(certFile, keyFile, "", caBundle))
	} else {
		opts = append(opts, ati.WithIdentityCert(certFile, keyFile))
	}

	client, err := ati.NewAgentClient(opts...)
	if err != nil {
		log.Fatalf("create ATI client: %v", err)
	}
	return client
}

func fetchAgentCard(client *ati.AgentClient, url string) bool {
	resp, err := client.Get(context.Background(), url)
	if err != nil {
		fmt.Printf("[FAILED] %v\n", err)
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(prettyJSON(body))

	o := resp.VerificationOutcome
	fmt.Println("\n--- Verification Result ---")
	fmt.Printf("  DNS Discovery (_ati record): %v\n", o.DNSDiscovered)
	fmt.Printf("  CA Chain Valid:              %v\n", o.CAChainValid)
	fmt.Printf("  SAN Matches:                %v\n", o.SANMatches)
	fmt.Printf("  Agent ID:                   %s\n", o.AgentID)
	fmt.Printf("  Peer ATI Name:              %s\n", o.PeerATIName)
	fmt.Printf("  Badge Verified:             %v\n", o.BadgeVerified)
	fmt.Printf("  DANE Verified:              %v\n", o.DANEVerified)
	fmt.Printf("  Achieved Level:             %s\n", o.AchievedLevel)
	if o.RequestedLevel != nil {
		fmt.Printf("  Requested Level:            %s\n", o.RequestedLevel)
	}
	fmt.Println()

	return true
}

type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type sendMessageParams struct {
	Message   a2aMessage `json:"message"`
	ContextID string     `json:"contextId,omitempty"`
}

type a2aMessage struct {
	Role  string    `json:"role"`
	Parts []a2aPart `json:"parts"`
}

type a2aPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

func a2aChat(client *ati.AgentClient, a2aURL string) {
	scanner := bufio.NewScanner(os.Stdin)
	contextID := ""
	reqID := 1

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		if input == "quit" || input == "exit" {
			break
		}

		req := jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      reqID,
			Method:  "message/send",
			Params: sendMessageParams{
				Message: a2aMessage{
					Role:  "user",
					Parts: []a2aPart{{Type: "text", Text: input}},
				},
				ContextID: contextID,
			},
		}
		reqID++

		resp, err := client.Post(context.Background(), a2aURL, req)
		if err != nil {
			fmt.Printf("[ERROR] %v\n\n", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		o := resp.VerificationOutcome
		fmt.Printf("[Verification] Level=%s Badge=%v DANE=%v\n",
			o.AchievedLevel, o.BadgeVerified, o.DANEVerified)

		var rpcResp struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &rpcResp); err != nil {
			fmt.Println(string(body))
			continue
		}
		if rpcResp.Error != nil {
			fmt.Printf("[RPC ERROR] %d: %s\n", rpcResp.Error.Code, rpcResp.Error.Message)
			continue
		}

		printTaskResult(rpcResp.Result)
		fmt.Println()

		var task map[string]any
		if json.Unmarshal(rpcResp.Result, &task) == nil {
			if cid, ok := task["contextId"].(string); ok && cid != "" {
				contextID = cid
			} else if tid, ok := task["id"].(string); ok && tid != "" {
				contextID = tid
			}
		}
	}
}

func printTaskResult(result json.RawMessage) {
	var task struct {
		Status struct {
			State string `json:"state"`
		} `json:"status"`
		Artifacts []struct {
			Parts []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(result, &task); err != nil {
		fmt.Println(prettyJSON(result))
		return
	}

	fmt.Printf("[Task] status=%s\n", task.Status.State)
	for _, a := range task.Artifacts {
		for _, p := range a.Parts {
			if p.Text != "" {
				fmt.Println(p.Text)
			}
		}
	}
}

func prettyJSON(data []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return string(data)
	}
	return buf.String()
}
