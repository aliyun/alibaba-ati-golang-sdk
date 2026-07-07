package backend

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
	url        string
	token      string
}

func NewClient(url, token string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 5 * time.Minute},
		url:        url,
		token:      token,
	}
}

type AgentRequest struct {
	Query          string         `json:"query"`
	ResponseMode   string         `json:"response_mode"`
	ConversationID string         `json:"conversation_id,omitempty"`
	User           string         `json:"user,omitempty"`
	Inputs         map[string]any `json:"inputs,omitempty"`
}

// SSEEvent represents a parsed backend SSE event with only the answer content.
type SSEEvent struct {
	Event          string
	Data           string // answer text (from agent_message events)
	ConversationID string
	Final          bool
}

// backendEvent is the raw JSON structure from the backend SSE stream.
type backendEvent struct {
	Event          string `json:"event"`
	Answer         string `json:"answer,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	FinishReason   string `json:"finish_reason,omitempty"`
}

func (c *Client) Call(ctx context.Context, req *AgentRequest) (string, error) {
	req.ResponseMode = "streaming"
	events, errc := c.CallStream(ctx, req)

	var result strings.Builder
	for evt := range events {
		if evt.Data != "" {
			result.WriteString(evt.Data)
		}
	}
	if err := <-errc; err != nil {
		return result.String(), err
	}
	return result.String(), nil
}

func (c *Client) CallStream(ctx context.Context, req *AgentRequest) (<-chan SSEEvent, <-chan error) {
	events := make(chan SSEEvent, 64)
	errc := make(chan error, 1)

	req.ResponseMode = "streaming"
	resp, err := c.doRequest(ctx, req)
	if err != nil {
		close(events)
		errc <- err
		return events, errc
	}

	go func() {
		defer resp.Body.Close()
		defer close(events)
		defer close(errc)

		scanner := bufio.NewScanner(resp.Body)
		var rawData strings.Builder

		for scanner.Scan() {
			line := scanner.Text()

			if line == "" {
				if rawData.Len() > 0 {
					evt := parseBackendEvent(rawData.String())
					if evt != nil {
						select {
						case events <- *evt:
						case <-ctx.Done():
							return
						}
					}
				}
				rawData.Reset()
				continue
			}

			if strings.HasPrefix(line, "data:") {
				if rawData.Len() > 0 {
					rawData.WriteByte('\n')
				}
				rawData.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}

		if rawData.Len() > 0 {
			if evt := parseBackendEvent(rawData.String()); evt != nil {
				events <- *evt
			}
		}

		if err := scanner.Err(); err != nil {
			errc <- err
		}
	}()

	return events, errc
}

// parseBackendEvent parses a backend SSE JSON payload.
// Only emits SSEEvents for agent_message (answer text) and message_end (final signal).
// Skips agent_thought and other internal events.
func parseBackendEvent(raw string) *SSEEvent {
	var be backendEvent
	if err := json.Unmarshal([]byte(raw), &be); err != nil {
		return nil
	}

	switch be.Event {
	case "agent_message", "message":
		if be.Answer == "" {
			return nil
		}
		return &SSEEvent{
			Event:          be.Event,
			Data:           be.Answer,
			ConversationID: be.ConversationID,
		}
	case "message_end":
		return &SSEEvent{
			Event:          be.Event,
			ConversationID: be.ConversationID,
			Final:          true,
		}
	default:
		return nil
	}
}

func (c *Client) doRequest(ctx context.Context, req *AgentRequest) (*http.Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	log.Printf("[Backend] POST %s body=%s", c.url, string(body))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("backend request: %w", err)
	}

	log.Printf("[Backend] response status=%d proto=%s", resp.StatusCode, resp.Proto)

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		log.Printf("[Backend] error body: %s", string(respBody))
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(respBody))
	}
	return resp, nil
}
