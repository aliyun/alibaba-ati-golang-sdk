package a2a

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func NewSSEWriter(w http.ResponseWriter) *SSEWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	return &SSEWriter{w: w, flusher: flusher}
}

func (s *SSEWriter) WriteStatusUpdate(evt TaskStatusUpdateEvent) {
	s.writeEvent("status", evt)
}

func (s *SSEWriter) WriteArtifactUpdate(evt TaskArtifactUpdateEvent) {
	s.writeEvent("artifact", evt)
}

func (s *SSEWriter) writeEvent(eventType string, data any) {
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", eventType, jsonData)
	if s.flusher != nil {
		s.flusher.Flush()
	}
}
