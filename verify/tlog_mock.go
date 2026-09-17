package verify

import (
	"context"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// MockTransparencyLogClient is a mock implementation of TransparencyLogClient for testing.
type MockTransparencyLogClient struct {
	tlResps map[string]*models.TLResponse
	errors  map[string]error
}

// NewMockTransparencyLogClient creates a new mock transparency log client.
func NewMockTransparencyLogClient() *MockTransparencyLogClient {
	return &MockTransparencyLogClient{
		tlResps: make(map[string]*models.TLResponse),
		errors:  make(map[string]error),
	}
}

// WithTLResponse adds a TL response for a URL.
func (c *MockTransparencyLogClient) WithTLResponse(url string, resp *models.TLResponse) *MockTransparencyLogClient {
	c.tlResps[url] = resp
	return c
}

// WithError configures an error for a URL.
func (c *MockTransparencyLogClient) WithError(url string, err error) *MockTransparencyLogClient {
	c.errors[url] = err
	return c
}

// FetchTLResponse fetches a TL response from the given URL.
func (c *MockTransparencyLogClient) FetchTLResponse(_ context.Context, url string) (*models.TLResponse, error) {
	if err, ok := c.errors[url]; ok {
		return nil, err
	}
	if resp, ok := c.tlResps[url]; ok {
		return resp, nil
	}
	return nil, &TlogError{
		Type: TlogErrorNotFound,
		URL:  url,
	}
}
