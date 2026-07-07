package a2a

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/backend"
	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/cmd/proxy/internal/jsonrpc"
)

const (
	errTaskNotFound    = -32001
	errTaskNotCanceled = -32002
)

type Handler struct {
	Store   *TaskStore
	Backend *backend.Client
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonrpc.NewErrorResponse(nil, jsonrpc.CodeParseError, "read body: "+err.Error()))
		return
	}

	req, err := jsonrpc.Parse(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, jsonrpc.NewErrorResponse(nil, jsonrpc.CodeParseError, err.Error()))
		return
	}

	switch req.Method {
	case "message/send":
		h.handleSendMessage(w, r, req)
	case "message/stream":
		h.handleSendStreamingMessage(w, r, req)
	case "tasks/get":
		h.handleGetTask(w, req)
	case "tasks/cancel":
		h.handleCancelTask(w, req)
	default:
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeMethodNotFound, "unknown method: "+req.Method))
	}
}

func (h *Handler) handleSendMessage(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request) {
	var params SendMessageParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, err.Error()))
		return
	}

	task := h.Store.Create(params.ContextID)

	query := extractText(params.Message)
	user := peerUser(r)

	backendReq := &backend.AgentRequest{
		Query:          query,
		ConversationID: task.ID,
		User:           user,
		Inputs:         map[string]any{},
	}

	respText, err := h.Backend.Call(r.Context(), backendReq)
	if err != nil {
		h.Store.Update(task.ID, func(t *Task) {
			t.Status = TaskStatus{
				State:   TaskStateFailed,
				Message: &Message{Role: "agent", Parts: []Part{{Type: "text", Text: err.Error()}}},
			}
		})
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInternalError, err.Error()))
		return
	}

	h.Store.Update(task.ID, func(t *Task) {
		t.Status = TaskStatus{State: TaskStateCompleted}
		t.Artifacts = []Artifact{{
			Parts: []Part{{Type: "text", Text: respText}},
			Index: 0,
		}}
	})

	updated, _ := h.Store.Get(task.ID)
	writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, updated))
}

func (h *Handler) handleSendStreamingMessage(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request) {
	var params SendMessageParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, err.Error()))
		return
	}

	task := h.Store.Create(params.ContextID)

	query := extractText(params.Message)
	user := peerUser(r)

	backendReq := &backend.AgentRequest{
		Query:          query,
		ConversationID: task.ID,
		User:           user,
		Inputs:         map[string]any{},
	}

	sse := NewSSEWriter(w)

	// Initial status: working
	h.Store.Update(task.ID, func(t *Task) {
		t.Status = TaskStatus{State: TaskStateWorking}
	})
	sse.WriteStatusUpdate(TaskStatusUpdateEvent{
		TaskID:    task.ID,
		ContextID: task.ContextID,
		Status:    TaskStatus{State: TaskStateWorking},
	})

	events, errc := h.Backend.CallStream(r.Context(), backendReq)

	var fullText strings.Builder
	artifactIdx := 0

	for evt := range events {
		if evt.Data == "" {
			continue
		}
		fullText.WriteString(evt.Data)

		isLast := false
		sse.WriteArtifactUpdate(TaskArtifactUpdateEvent{
			TaskID:    task.ID,
			ContextID: task.ContextID,
			Artifact: Artifact{
				Parts:     []Part{{Type: "text", Text: evt.Data}},
				Index:     artifactIdx,
				LastChunk: &isLast,
			},
		})
		artifactIdx++
	}

	if err := <-errc; err != nil {
		log.Printf("[A2A] stream error: %v", err)
		h.Store.Update(task.ID, func(t *Task) {
			t.Status = TaskStatus{
				State:   TaskStateFailed,
				Message: &Message{Role: "agent", Parts: []Part{{Type: "text", Text: err.Error()}}},
			}
		})
		sse.WriteStatusUpdate(TaskStatusUpdateEvent{
			TaskID: task.ID, ContextID: task.ContextID,
			Status: TaskStatus{State: TaskStateFailed}, Final: true,
		})
		return
	}

	h.Store.Update(task.ID, func(t *Task) {
		t.Status = TaskStatus{State: TaskStateCompleted}
		t.Artifacts = []Artifact{{
			Parts: []Part{{Type: "text", Text: fullText.String()}},
			Index: 0,
		}}
	})

	lastChunk := true
	sse.WriteArtifactUpdate(TaskArtifactUpdateEvent{
		TaskID:    task.ID,
		ContextID: task.ContextID,
		Artifact: Artifact{
			Parts:     []Part{{Type: "text", Text: ""}},
			Index:     artifactIdx,
			LastChunk: &lastChunk,
		},
	})
	sse.WriteStatusUpdate(TaskStatusUpdateEvent{
		TaskID: task.ID, ContextID: task.ContextID,
		Status: TaskStatus{State: TaskStateCompleted}, Final: true,
	})
}

func (h *Handler) handleGetTask(w http.ResponseWriter, req *jsonrpc.Request) {
	var params GetTaskParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, err.Error()))
		return
	}

	task, ok := h.Store.Get(params.TaskID)
	if !ok {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, errTaskNotFound, "task not found"))
		return
	}
	writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, task))
}

func (h *Handler) handleCancelTask(w http.ResponseWriter, req *jsonrpc.Request) {
	var params CancelTaskParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, jsonrpc.CodeInvalidParams, err.Error()))
		return
	}

	task, ok := h.Store.Get(params.TaskID)
	if !ok {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, errTaskNotFound, "task not found"))
		return
	}
	if task.Status.State.IsTerminal() {
		writeJSON(w, http.StatusOK, jsonrpc.NewErrorResponse(req.ID, errTaskNotCanceled, "task already in terminal state"))
		return
	}

	h.Store.Update(params.TaskID, func(t *Task) {
		t.Status = TaskStatus{State: TaskStateCanceled}
	})
	updated, _ := h.Store.Get(params.TaskID)
	writeJSON(w, http.StatusOK, jsonrpc.NewResponse(req.ID, updated))
}

func extractText(msg Message) string {
	var sb strings.Builder
	for _, p := range msg.Parts {
		if p.Type == "text" && p.Text != "" {
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
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
