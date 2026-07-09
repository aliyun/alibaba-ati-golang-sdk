package ati

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
	"github.com/aliyun/alibaba-ati-golang-sdk/verify"
)

// DiagnoseStep represents a single step in the diagnostic chain.
type DiagnoseStep struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "PASS", "FAIL", "SKIP"
	Duration string `json:"duration"`
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
}

// DiagnoseResult holds the full diagnostic output.
type DiagnoseResult struct {
	Host      string         `json:"host"`
	Timestamp string         `json:"timestamp"`
	Steps     []DiagnoseStep `json:"steps"`
	Summary   string         `json:"summary"`
}

// String returns a human-readable diagnostic report.
func (r *DiagnoseResult) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("ATI Diagnostic Report for %s\n", r.Host))
	b.WriteString(fmt.Sprintf("Time: %s\n", r.Timestamp))
	b.WriteString(strings.Repeat("-", 60) + "\n")

	for i, step := range r.Steps {
		icon := "?"
		switch step.Status {
		case "PASS":
			icon = "OK"
		case "FAIL":
			icon = "FAIL"
		case "SKIP":
			icon = "SKIP"
		}
		b.WriteString(fmt.Sprintf("[%d] %-30s [%s] (%s)\n", i+1, step.Name, icon, step.Duration))
		if step.Detail != "" {
			b.WriteString(fmt.Sprintf("    %s\n", step.Detail))
		}
		if step.Error != "" {
			b.WriteString(fmt.Sprintf("    Error: %s\n", step.Error))
		}
	}

	b.WriteString(strings.Repeat("-", 60) + "\n")
	b.WriteString(fmt.Sprintf("Result: %s\n", r.Summary))
	return b.String()
}

// JSON returns the diagnostic result as indented JSON.
func (r *DiagnoseResult) JSON() string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}

// DiagnoseOption configures the Diagnose function.
type DiagnoseOption func(*diagnoseConfig)

type diagnoseConfig struct {
	dnsResolver verify.DNSResolver
	tlogClient  verify.TransparencyLogClient
	tlBaseURL   string
}

// WithDiagnoseDNSResolver sets a custom DNS resolver for diagnostics.
func WithDiagnoseDNSResolver(r verify.DNSResolver) DiagnoseOption {
	return func(c *diagnoseConfig) {
		c.dnsResolver = r
	}
}

// WithDiagnoseTLogClient sets a custom TL client for diagnostics.
func WithDiagnoseTLogClient(t verify.TransparencyLogClient) DiagnoseOption {
	return func(c *diagnoseConfig) {
		c.tlogClient = t
	}
}

// withDiagnoseTLBaseURL sets a custom TL base URL for diagnostics (test only).
func withDiagnoseTLBaseURL(url string) DiagnoseOption {
	return func(c *diagnoseConfig) {
		c.tlBaseURL = url
	}
}

// Diagnose runs the full ATI verification chain for a host and returns a step-by-step report.
func Diagnose(ctx context.Context, host string, opts ...DiagnoseOption) (*DiagnoseResult, error) {
	cfg := &diagnoseConfig{
		dnsResolver: verify.NewStandardDNSResolver(),
		tlogClient:  verify.NewHTTPTransparencyLogClient(),
		tlBaseURL:   "https://tl.ansagent.cn:8180/ans/api/v1",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	result := &DiagnoseResult{
		Host:      host,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	allPass := true

	// Step 1: Validate host
	start := time.Now()
	fqdn, err := models.NewFqdn(host)
	step1 := DiagnoseStep{
		Name:     "Host Validation",
		Duration: time.Since(start).String(),
	}
	if err != nil {
		step1.Status = "FAIL"
		step1.Error = err.Error()
		allPass = false
		result.Steps = append(result.Steps, step1)
		result.Summary = "FAIL (invalid host)"
		return result, nil
	}
	step1.Status = "PASS"
	step1.Detail = fmt.Sprintf("FQDN: %s", fqdn.String())
	result.Steps = append(result.Steps, step1)

	// Step 2: DNS Discovery (_ati TXT)
	start = time.Now()
	discoveryResult, err := cfg.dnsResolver.LookupATIDiscovery(ctx, fqdn)
	step2 := DiagnoseStep{
		Name:     "DNS Discovery (_ati TXT)",
		Duration: time.Since(start).String(),
	}
	if err != nil {
		step2.Status = "FAIL"
		step2.Error = err.Error()
		allPass = false
		result.Steps = append(result.Steps, step2)
		result.Summary = "FAIL (DNS discovery error)"
		return result, nil
	}
	if !discoveryResult.Found || len(discoveryResult.Records) == 0 {
		step2.Status = "FAIL"
		step2.Error = "no _ati TXT record found"
		allPass = false
		result.Steps = append(result.Steps, step2)
		result.Summary = "FAIL (not an ATI agent)"
		return result, nil
	}
	agentID := discoveryResult.Records[0].ID
	step2.Status = "PASS"
	step2.Detail = fmt.Sprintf("AgentID: %s, Mode: %s", sanitize(agentID, 12), discoveryResult.Records[0].Mode)
	result.Steps = append(result.Steps, step2)

	// Step 3: DNS Badge Lookup (_ati-badge TXT)
	start = time.Now()
	badgeRecord, err := cfg.dnsResolver.FindPreferredBadge(ctx, fqdn)
	step3 := DiagnoseStep{
		Name:     "DNS Badge Lookup (_ati-badge)",
		Duration: time.Since(start).String(),
	}
	if err != nil || badgeRecord == nil {
		step3.Status = "SKIP"
		step3.Detail = "no badge record found (non-fatal)"
		if err != nil {
			step3.Error = err.Error()
		}
	} else {
		step3.Status = "PASS"
		step3.Detail = fmt.Sprintf("URL: %s", sanitize(badgeRecord.URL, 50))
	}
	result.Steps = append(result.Steps, step3)

	// Step 4: TL Response Fetch
	start = time.Now()
	tlURL := fmt.Sprintf("%s/tl/agents/%s/logs/latest", cfg.tlBaseURL, agentID)
	tlResp, err := cfg.tlogClient.FetchTLResponse(ctx, tlURL)
	step4 := DiagnoseStep{
		Name:     "TL Response Fetch",
		Duration: time.Since(start).String(),
	}
	if err != nil {
		step4.Status = "FAIL"
		step4.Error = err.Error()
		allPass = false
	} else {
		step4.Status = "PASS"
		step4.Detail = fmt.Sprintf("Status: %s, Agent: %s", tlResp.Status, sanitize(tlResp.Payload.AgentName, 30))
	}
	result.Steps = append(result.Steps, step4)

	// Step 5: Seal Signature Verification
	step5 := DiagnoseStep{Name: "Seal Signature"}
	if tlResp != nil {
		start = time.Now()
		sealErr := verify.VerifySealSignature(tlResp, nil)
		step5.Duration = time.Since(start).String()
		if sealErr != nil {
			step5.Status = "FAIL"
			step5.Error = sealErr.Error()
			allPass = false
		} else {
			step5.Status = "PASS"
			step5.Detail = fmt.Sprintf("Algorithm: %s, KeyID: %s",
				tlResp.Seal.SignatureAlgorithm, sanitize(tlResp.Seal.KeyID, 20))
		}
	} else {
		step5.Status = "SKIP"
		step5.Detail = "no TL response to verify"
		step5.Duration = "0s"
	}
	result.Steps = append(result.Steps, step5)

	// Step 6: Merkle Inclusion Proof Verification
	step6 := DiagnoseStep{Name: "Merkle Inclusion Proof"}
	if tlResp != nil {
		start = time.Now()
		merkleErr := verify.VerifyInclusionProof(tlResp)
		step6.Duration = time.Since(start).String()
		if merkleErr != nil {
			step6.Status = "FAIL"
			step6.Error = merkleErr.Error()
			allPass = false
		} else {
			step6.Status = "PASS"
			step6.Detail = fmt.Sprintf("TreeSize: %d, LeafIndex: %d",
				tlResp.MerkleProof.TreeSize, tlResp.MerkleProof.LeafIndex)
		}
	} else {
		step6.Status = "SKIP"
		step6.Detail = "no TL response to verify"
		step6.Duration = "0s"
	}
	result.Steps = append(result.Steps, step6)

	// Step 7: Producer Signature Verification
	step7 := DiagnoseStep{Name: "Producer Signature"}
	if tlResp != nil {
		start = time.Now()
		step7.Duration = time.Since(start).String()
		if tlResp.EvidenceRef.SignatureRequired {
			step7.Status = "SKIP"
			step7.Detail = fmt.Sprintf("SubmitterID: %s (no keys configured for verification)",
				sanitize(tlResp.EvidenceRef.SubmitterID, 20))
		} else {
			step7.Status = "SKIP"
			step7.Detail = "signatureRequired=false, producer signature not required"
		}
	} else {
		step7.Status = "SKIP"
		step7.Detail = "no TL response"
		step7.Duration = "0s"
	}
	result.Steps = append(result.Steps, step7)

	// Step 8: Certificate Fingerprints
	step8 := DiagnoseStep{Name: "Certificate Fingerprints"}
	if tlResp != nil {
		idFP := tlResp.Payload.IdentityCertFingerprint()
		srvFP := tlResp.Payload.ServerCertFingerprint()
		if idFP != "" || srvFP != "" {
			step8.Status = "PASS"
			var details []string
			if idFP != "" {
				details = append(details, fmt.Sprintf("Identity: %s...", sanitize(idFP, 20)))
			}
			if srvFP != "" {
				details = append(details, fmt.Sprintf("Server: %s...", sanitize(srvFP, 20)))
			}
			step8.Detail = strings.Join(details, ", ")
		} else {
			step8.Status = "SKIP"
			step8.Detail = "no certificate fingerprints in payload"
		}
		step8.Duration = "0s"
	} else {
		step8.Status = "SKIP"
		step8.Detail = "no TL response"
		step8.Duration = "0s"
	}
	result.Steps = append(result.Steps, step8)

	// Step 9: Agent Status
	step9 := DiagnoseStep{Name: "Agent Status"}
	if tlResp != nil {
		agentStatus := tlResp.Payload.AgentStatus
		if agentStatus != "" {
			status := models.TLAgentStatus(strings.ToUpper(agentStatus))
			if status.IsTerminal() {
				step9.Status = "FAIL"
				step9.Error = fmt.Sprintf("agent status %s does not allow connections", status)
				allPass = false
			} else {
				step9.Status = "PASS"
			}
			step9.Detail = fmt.Sprintf("AgentStatus: %s", agentStatus)
		} else {
			step9.Status = "SKIP"
			step9.Detail = "no agent status in payload"
		}
		step9.Duration = "0s"
	} else {
		step9.Status = "SKIP"
		step9.Detail = "no TL response"
		step9.Duration = "0s"
	}
	result.Steps = append(result.Steps, step9)

	if allPass {
		result.Summary = "ALL PASS"
	} else {
		result.Summary = "PARTIAL FAIL"
	}

	return result, nil
}

// sanitize truncates a string and appends "..." if it exceeds maxLen.
func sanitize(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
