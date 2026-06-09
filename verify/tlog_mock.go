package verify

import (
	"context"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/models"
)

// MockTransparencyLogClient is a mock implementation of TransparencyLogClient for testing.
type MockTransparencyLogClient struct {
	badges    map[string]*models.Badge
	tlResps   map[string]*models.TLResponse
	errors    map[string]error
}

// NewMockTransparencyLogClient creates a new mock transparency log client.
func NewMockTransparencyLogClient() *MockTransparencyLogClient {
	return &MockTransparencyLogClient{
		badges:  make(map[string]*models.Badge),
		tlResps: make(map[string]*models.TLResponse),
		errors:  make(map[string]error),
	}
}

// WithBadge adds a badge for a URL.
func (c *MockTransparencyLogClient) WithBadge(url string, badge *models.Badge) *MockTransparencyLogClient {
	c.badges[url] = badge
	return c
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

// FetchBadge fetches a badge from the given URL.
func (c *MockTransparencyLogClient) FetchBadge(_ context.Context, url string) (*models.Badge, error) {
	if err, ok := c.errors[url]; ok {
		return nil, err
	}
	if badge, ok := c.badges[url]; ok {
		return badge, nil
	}
	return nil, &TlogError{
		Type: TlogErrorNotFound,
		URL:  url,
	}
}

// FetchTLResponse fetches a three-layer nested TL response from the given URL.
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
