package registry

// raConfig holds configuration for the RA API client.
type raConfig struct {
	accessKeyID     string
	accessKeySecret string
	endpoint        string
}

func defaultRAConfig() *raConfig {
	return &raConfig{
		endpoint: "https://ra.ansagent.cn:8180/ans/api/v1",
	}
}

// RAClientOption configures a RAClient.
type RAClientOption func(*raConfig)

// WithAccessKeyID sets the access key ID.
func WithAccessKeyID(id string) RAClientOption {
	return func(c *raConfig) { c.accessKeyID = id }
}

// WithAccessKeySecret sets the access key secret.
func WithAccessKeySecret(secret string) RAClientOption {
	return func(c *raConfig) { c.accessKeySecret = secret }
}

// WithRAEndpoint sets the RA API endpoint.
func WithRAEndpoint(endpoint string) RAClientOption {
	return func(c *raConfig) { c.endpoint = endpoint }
}
