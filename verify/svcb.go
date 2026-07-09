package verify

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// SVCBResult holds parsed HTTPS/SVCB (Type 65) DNS record data per spec §4.1.
type SVCBResult struct {
	Found     bool
	ALPN      []string
	Port      uint16
	ECHConfig []byte
	Target    string
}

// LookupHTTPSSVCB queries HTTPS (Type 65) DNS records for the given FQDN.
func LookupHTTPSSVCB(ctx context.Context, server string, fqdn models.Fqdn) (*SVCBResult, error) {
	if server == "" {
		server = "8.8.8.8:53"
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn.String()), dns.TypeHTTPS)
	msg.RecursionDesired = true

	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	r, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return &SVCBResult{Found: false}, nil
	}

	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		return &SVCBResult{Found: false}, nil
	}

	result := &SVCBResult{Found: true}

	for _, rr := range r.Answer {
		svcb, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}

		if svcb.Target != "" && svcb.Target != "." {
			result.Target = svcb.Target
		}

		for _, kv := range svcb.Value {
			switch v := kv.(type) {
			case *dns.SVCBAlpn:
				result.ALPN = v.Alpn
			case *dns.SVCBPort:
				result.Port = v.Port
			case *dns.SVCBECHConfig:
				result.ECHConfig = v.ECH
			}
		}
	}

	return result, nil
}
