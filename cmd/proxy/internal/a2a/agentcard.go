package a2a

import (
	"encoding/json"
	"net/http"
)

type AgentCardConfig struct {
	Name        string
	Description string
	URL         string
	Version     string
}

func NewAgentCardHandler(cfg AgentCardConfig) http.HandlerFunc {
	card := AgentCard{
		Name:        cfg.Name,
		Description: cfg.Description,
		URL:         cfg.URL,
		Version:     cfg.Version,
		Capabilities: Capabilities{
			Streaming:         true,
			PushNotifications: false,
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills: []Skill{
			{
				ID:          "general",
				Name:        "General Assistant",
				Description: "General-purpose AI agent",
				Tags:        []string{"general", "assistant"},
			},
		},
	}

	cardJSON, _ := json.MarshalIndent(card, "", "  ")

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(cardJSON)
	}
}
