package cmd

import (
	"errors"
	"strings"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/registry"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/ati-cli/internal/config"
)

const (
	// apiKeyParts is the expected number of parts in an API key (key:secret)
	apiKeyParts = 2
)

// createClient creates an ATI client with API key authentication
// API key format: key:secret
func createClient(cfg *config.Config) (*registry.Client, error) {
	// API key format: key:secret
	parts := strings.SplitN(cfg.APIKey, ":", apiKeyParts)
	if len(parts) != apiKeyParts {
		return nil, errors.New("invalid API key format, expected key:secret")
	}

	opts := []registry.Option{
		registry.WithBaseURL(cfg.BaseURL),
		registry.WithVerbose(cfg.Verbose),
		registry.WithAPIKey(parts[0], parts[1]),
	}

	return registry.NewClient(opts...)
}
