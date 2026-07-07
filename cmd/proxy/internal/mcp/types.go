package mcp

const ProtocolVersion = "2025-03-26"

type InitializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	ClientInfo      EntityInfo `json:"clientInfo"`
	Capabilities    any        `json:"capabilities,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string     `json:"protocolVersion"`
	ServerInfo      EntityInfo `json:"serverInfo"`
	Capabilities    ServerCaps `json:"capabilities"`
	Instructions    string     `json:"instructions,omitempty"`
}

type EntityInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerCaps struct {
	Tools *ToolsCap `json:"tools,omitempty"`
}

type ToolsCap struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema *JSONSchema `json:"inputSchema"`
}

type JSONSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]*JSONSchema `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type ToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
