package verify

import (
	"context"
	crypto_tls "crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// Default HTTP client configuration values.
const (
	defaultHTTPTimeoutSeconds = 30
	maxErrorResponseBodyBytes = 1024
	maxTLResponseBodyBytes    = 1 << 20 // 1 MB
)

// TransparencyLogClient is the interface for fetching TL responses from the transparency log.
type TransparencyLogClient interface {
	// FetchTLResponse fetches a TL response from the given URL.
	FetchTLResponse(ctx context.Context, url string) (*models.TLResponse, error)
}

// HTTPTransparencyLogClient is an HTTP-based implementation of TransparencyLogClient.
type HTTPTransparencyLogClient struct {
	httpClient *http.Client
}

// NewHTTPTransparencyLogClient creates a new HTTP-based transparency log client.
func NewHTTPTransparencyLogClient() *HTTPTransparencyLogClient {
	return &HTTPTransparencyLogClient{
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeoutSeconds * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &crypto_tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// WithHTTPClient sets a custom HTTP client.
func (c *HTTPTransparencyLogClient) WithHTTPClient(client *http.Client) *HTTPTransparencyLogClient {
	c.httpClient = client
	return c
}

// WithTimeout sets the request timeout.
func (c *HTTPTransparencyLogClient) WithTimeout(timeout time.Duration) *HTTPTransparencyLogClient {
	c.httpClient.Timeout = timeout
	return c
}

// FetchTLResponse fetches a TL response from the given URL.
func (c *HTTPTransparencyLogClient) FetchTLResponse(ctx context.Context, url string) (*models.TLResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &TlogError{
			Type:   TlogErrorInvalidResponse,
			URL:    url,
			Reason: fmt.Sprintf("failed to create request: %v", err),
		}
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &TlogError{
			Type:   TlogErrorServiceUnavailable,
			URL:    url,
			Reason: err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &TlogError{
			Type:     TlogErrorNotFound,
			URL:      url,
			HTTPCode: resp.StatusCode,
		}
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &TlogError{
			Type:     TlogErrorServiceUnavailable,
			URL:      url,
			HTTPCode: resp.StatusCode,
		}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseBodyBytes))
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &TlogError{
			Type:     TlogErrorInvalidResponse,
			URL:      url,
			HTTPCode: resp.StatusCode,
			Reason:   fmt.Sprintf("unexpected status %d: %s", resp.StatusCode, string(body)),
		}
	}

	var tlResp models.TLResponse
	limitedReader := io.LimitReader(resp.Body, maxTLResponseBodyBytes)
	if err := json.NewDecoder(limitedReader).Decode(&tlResp); err != nil {
		return nil, &TlogError{
			Type:   TlogErrorInvalidResponse,
			URL:    url,
			Reason: fmt.Sprintf("failed to decode TL response: %v", err),
		}
	}

	return &tlResp, nil
}
