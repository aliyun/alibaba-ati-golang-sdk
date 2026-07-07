package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/backend"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/jsonrpc"
)

type Handler struct {
	Sessions   *SessionStore
	Backend    *backend.Client
	ServerInfo EntityInfo
	tools      []Tool
}

func NewHandler(sessions *SessionStore, bc *backend.Client, serverInfo EntityInfo) *Handler {
	return &Handler{
		Sessions:   sessions,
		Backend:    bc,
		ServerInfo: serverInfo,
		tools: []Tool{
			{
				Name:        "ask_agent",
				Description: "Send a query to the AI agent and get a response",
				InputSchema: &JSONSchema{
					Type: "object",
					Properties: map[string]*JSONSchema{
						"query":           {Type: "string"},
						"conversation_id": {Type: "string"},
					},
					Required: []string{"query"},
				},
			},
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.handleSSEStream(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		h.handleDeleteSession(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonrpc.NewErrorResponse(nil, jsonrpc.CodeParseError, err.Error()))
		return
	}

	req, err := jsonrpc.Parse(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonrpc.NewErrorResponse(nil, jsonrpc.CodeParseError, err.Error()))
		return
	}

	// initialize does not require a session
	if req.Method == "initialize" {
		h.handleInitialize(w, req)
		return
	}

	// notifications don't require a response
	if req.Method == "notifications/initialized" {
		sessionID := r.Header.Get("Mcp-Session-Id")
		if sess, ok := h.Sessions.Get(sessionID); ok {
			sess.Initialized = true
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// All other methods require a valid session
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}
	if _, ok := h.Sessions.Get(sessionID); !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	switch req.Method {
	case "tools/list":
		h.handleToolsList(w, req)
	case "tools/call":
		h.handleToolsCall(w, r, req)
	case "ping":
		writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, map[string]any{}))
	default:
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeMethodNotFound, "unknown method: "+req.Method))
	}
}

func (h *Handler) handleInitialize(w http.ResponseWriter, req *jsonrpc.Request) {
	sess := h.Sessions.Create()

	result := InitializeResult{
		ProtocolVersion: ProtocolVersion,
		ServerInfo:      h.ServerInfo,
		Capabilities: ServerCaps{
			Tools: &ToolsCap{ListChanged: false},
		},
	}

	w.Header().Set("Mcp-Session-Id", sess.ID)
	writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, result))
}

func (h *Handler) handleToolsList(w http.ResponseWriter, req *jsonrpc.Request) {
	writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, ToolsListResult{Tools: h.tools}))
}

func (h *Handler) handleToolsCall(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, err.Error()))
		return
	}

	if params.Name != "ask_agent" {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, "unknown tool: "+params.Name))
		return
	}

	query, _ := params.Arguments["query"].(string)
	if query == "" {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, "query is required"))
		return
	}
	convID, _ := params.Arguments["conversation_id"].(string)

	user := peerUser(r)

	backendReq := &backend.AgentRequest{
		Query:          query,
		ConversationID: convID,
		User:           user,
		Inputs:         map[string]any{},
	}

	// Check if client accepts SSE
	accept := r.Header.Get("Accept")
	wantsSSE := strings.Contains(accept, "text/event-stream")

	if wantsSSE {
		h.handleToolsCallStream(w, r, req, backendReq)
		return
	}

	respBody, err := h.Backend.Call(r.Context(), backendReq)
	if err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		}))
		return
	}

	writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, ToolResult{
		Content: []ToolContent{{Type: "text", Text: string(respBody)}},
	}))
}

func (h *Handler) handleToolsCallStream(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, backendReq *backend.AgentRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInternalError, "streaming not supported"))
		return
	}

	events, errc := h.Backend.CallStream(r.Context(), backendReq)

	var fullText strings.Builder

	for evt := range events {
		if evt.Data != "" {
			fullText.WriteString(evt.Data)
		}
	}

	if err := <-errc; err != nil {
		result := jsonrpc.NewResponse(req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		})
		data, _ := json.Marshal(result)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return
	}

	result := jsonrpc.NewResponse(req.ID, ToolResult{
		Content: []ToolContent{{Type: "text", Text: fullText.String()}},
	})
	data, _ := json.Marshal(result)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

func (h *Handler) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}
	if _, ok := h.Sessions.Get(sessionID); !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	// Keep the connection open until client disconnects.
	// Server-initiated messages would be sent here in future.
	<-r.Context().Done()
}

func (h *Handler) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}
	h.Sessions.Delete(sessionID)
	w.WriteHeader(http.StatusOK)
}

func peerUser(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		for _, uri := range r.TLS.PeerCertificates[0].URIs {
			if strings.HasPrefix(uri.String(), "ati://") {
				return uri.String()
			}
		}
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return "anonymous"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
