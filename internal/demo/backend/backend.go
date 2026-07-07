// Package backend implements the ATI demo weather agent (Agent B). It exposes a
// plain-HTTP /chat endpoint driven by DashScope function-calling plus Open-Meteo
// weather data, and an /mcp endpoint for agent-card/discovery compatibility.
package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds the weather agent's runtime configuration.
type Config struct {
	ListenAddr string
	DashKey    string
	DashModel  string
}

// Run starts the weather agent HTTP server and blocks until it exits.
func Run(cfg Config) error {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":7100"
	}
	if cfg.DashModel == "" {
		cfg.DashModel = "qwen-plus"
	}

	agent := &WeatherAgent{
		dashKey:   cfg.DashKey,
		dashModel: cfg.DashModel,
		http:      &http.Client{Timeout: 30 * time.Second},
		convos:    make(map[string][]oaMessage),
	}
	if cfg.DashKey == "" {
		slog.Warn("[backend] DASHSCOPE_API_KEY not set — weather agent will run in degraded (no-LLM) mode")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", handleMCP)
	mux.HandleFunc("POST /chat", agent.handleChat)

	log.Printf("ati-demo-backend (weather agent) listening on %s (model=%s)", cfg.ListenAddr, cfg.DashModel)
	return http.ListenAndServe(cfg.ListenAddr, mux)
}

// --- JSON-RPC (MCP) types, kept for the /mcp agent-card path ---

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// --- Weather Agent ---

// WeatherAgent is a conversational weather-forecast agent. It uses DashScope
// (qwen) function-calling to drive the dialogue and calls Open-Meteo for real
// forecast data. Conversation history is kept in memory per conversationId so
// the agent can handle multi-turn follow-ups.
type WeatherAgent struct {
	dashKey   string
	dashModel string
	http      *http.Client

	mu     sync.Mutex
	convos map[string][]oaMessage
}

const weatherSystemPrompt = `你是 Agent B，一个掌握真实天气数据、并且熟悉各地本地出行信息的专家 Agent。你正在与另一个 Agent（Agent A）对话，A 会代表最终用户向你提问。
你的能力：
- 天气：需要天气数据时调用 get_weather 工具，基于返回的真实天气作答，不要编造天气。
- 本地出行：熟悉各城市可以爬的山、可以逛的商场/景点/街区，能结合当天天气给出具体、真实的地点推荐（例如晴天推荐爬哪座山，下雨天推荐逛哪个商场）。
回答要求：
- 简洁、专业、直接回答 A 的问题，给出具体地点名称和理由，不要反问、不要寒暄。
- 如果 A 问天气就先查天气再回答；如果 A 问去哪玩就结合天气给出真实的地点推荐。`

type oaMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function oaFunctionCall `json:"function"`
}

type oaFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

func (a *WeatherAgent) handleChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message        string `json:"message"`
		ConversationID string `json:"conversationId"`
		User           string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeJSON(w, map[string]any{"reply": "请问你想了解哪个城市的天气呢？", "conversationId": req.ConversationID})
		return
	}

	cid := req.ConversationID
	if cid == "" {
		cid = fmt.Sprintf("conv-%d", time.Now().UnixNano())
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	reply, err := a.respond(ctx, cid, req.Message)
	if err != nil {
		slog.Error("[backend] weather agent failed", "error", err)
		reply = "抱歉，天气助手暂时出了点问题：" + err.Error()
	}

	writeJSON(w, map[string]any{"reply": reply, "conversationId": cid})
}

// respond appends the user message to the conversation, runs the LLM
// tool-calling loop, stores and returns the assistant reply.
func (a *WeatherAgent) respond(ctx context.Context, cid, userMessage string) (string, error) {
	a.mu.Lock()
	history, ok := a.convos[cid]
	if !ok {
		history = []oaMessage{{Role: "system", Content: weatherSystemPrompt}}
	}
	history = append(history, oaMessage{Role: "user", Content: userMessage})
	a.mu.Unlock()

	if a.dashKey == "" {
		reply := a.degradedReply(ctx, userMessage)
		a.mu.Lock()
		a.convos[cid] = append(history, oaMessage{Role: "assistant", Content: reply})
		a.mu.Unlock()
		return reply, nil
	}

	// Tool-calling loop: let the model call get_weather, feed results back,
	// then produce the final natural-language reply.
	const maxRounds = 4
	for round := 0; round < maxRounds; round++ {
		msg, err := a.callLLM(ctx, history)
		if err != nil {
			return "", err
		}
		history = append(history, msg)

		if len(msg.ToolCalls) == 0 {
			a.mu.Lock()
			a.convos[cid] = history
			a.mu.Unlock()
			return msg.Content, nil
		}

		for _, tc := range msg.ToolCalls {
			result := a.execTool(ctx, tc)
			history = append(history, oaMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Content:    result,
			})
		}
	}

	// Ran out of rounds — return whatever the last assistant text was.
	a.mu.Lock()
	a.convos[cid] = history
	a.mu.Unlock()
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].Role == "assistant" && history[i].Content != "" {
			return history[i].Content, nil
		}
	}
	return "抱歉，我没能查到有用的天气信息，可以换个城市再试试吗？", nil
}

func weatherTools() []map[string]any {
	return []map[string]any{
		{
			"type": "function",
			"function": map[string]any{
				"name":        "get_weather",
				"description": "查询指定城市未来几天的真实天气预报（气温、天气状况、降水概率）",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"city": map[string]any{
							"type":        "string",
							"description": "城市名称，例如 杭州、北京、黄山",
						},
						"days": map[string]any{
							"type":        "integer",
							"description": "预报天数，范围 1-7，默认 3",
						},
					},
					"required": []string{"city"},
				},
			},
		},
	}
}

func (a *WeatherAgent) callLLM(ctx context.Context, messages []oaMessage) (oaMessage, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"model":       a.dashModel,
		"messages":    messages,
		"tools":       weatherTools(),
		"tool_choice": "auto",
	})

	const dashScopeURL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", dashScopeURL, bytes.NewReader(reqBody))
	if err != nil {
		return oaMessage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.dashKey)

	resp, err := a.http.Do(req)
	if err != nil {
		return oaMessage{}, fmt.Errorf("dashscope request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return oaMessage{}, fmt.Errorf("dashscope returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message oaMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return oaMessage{}, fmt.Errorf("dashscope response parse error: %w", err)
	}
	if len(result.Choices) == 0 {
		return oaMessage{}, fmt.Errorf("dashscope returned no choices")
	}
	msg := result.Choices[0].Message
	msg.Role = "assistant"
	return msg, nil
}

func (a *WeatherAgent) execTool(ctx context.Context, tc oaToolCall) string {
	if tc.Function.Name != "get_weather" {
		return fmt.Sprintf("未知工具: %s", tc.Function.Name)
	}
	var args struct {
		City string `json:"city"`
		Days int    `json:"days"`
	}
	json.Unmarshal([]byte(tc.Function.Arguments), &args)
	if args.Days <= 0 || args.Days > 7 {
		args.Days = 3
	}
	forecast, err := a.getWeather(ctx, args.City, args.Days)
	if err != nil {
		slog.Warn("[backend] get_weather failed", "city", args.City, "error", err)
		return fmt.Sprintf("查询 %s 天气失败: %s", args.City, err.Error())
	}
	slog.Info("[backend] get_weather ok", "city", args.City, "days", args.Days)
	return forecast
}

// --- Open-Meteo integration (no API key required) ---

func (a *WeatherAgent) getWeather(ctx context.Context, city string, days int) (string, error) {
	lat, lon, resolved, err := a.geocode(ctx, city)
	if err != nil {
		return "", err
	}

	fq := url.Values{}
	fq.Set("latitude", strconv.FormatFloat(lat, 'f', 4, 64))
	fq.Set("longitude", strconv.FormatFloat(lon, 'f', 4, 64))
	fq.Set("daily", "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max")
	fq.Set("timezone", "auto")
	fq.Set("forecast_days", strconv.Itoa(days))
	endpoint := "https://api.open-meteo.com/v1/forecast?" + fq.Encode()

	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("forecast request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("forecast returned %d", resp.StatusCode)
	}

	var fc struct {
		Daily struct {
			Time          []string  `json:"time"`
			WeatherCode   []int     `json:"weather_code"`
			TempMax       []float64 `json:"temperature_2m_max"`
			TempMin       []float64 `json:"temperature_2m_min"`
			PrecipProbMax []int     `json:"precipitation_probability_max"`
		} `json:"daily"`
	}
	if err := json.Unmarshal(body, &fc); err != nil {
		return "", fmt.Errorf("forecast parse error: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s 未来 %d 天天气预报（数据来源 Open-Meteo）:\n", resolved, len(fc.Daily.Time))
	for i := range fc.Daily.Time {
		desc := weatherCodeDesc(fc.Daily.WeatherCode[i])
		precip := ""
		if i < len(fc.Daily.PrecipProbMax) {
			precip = fmt.Sprintf("，降水概率 %d%%", fc.Daily.PrecipProbMax[i])
		}
		fmt.Fprintf(&sb, "- %s: %s，气温 %.0f~%.0f℃%s\n",
			fc.Daily.Time[i], desc, fc.Daily.TempMin[i], fc.Daily.TempMax[i], precip)
	}
	return sb.String(), nil
}

func (a *WeatherAgent) geocode(ctx context.Context, city string) (lat, lon float64, name string, err error) {
	gq := url.Values{}
	gq.Set("name", city)
	gq.Set("count", "1")
	gq.Set("language", "zh")
	gq.Set("format", "json")
	endpoint := "https://geocoding-api.open-meteo.com/v1/search?" + gq.Encode()

	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, 0, "", fmt.Errorf("geocoding request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var geo struct {
		Results []struct {
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
			Name      string  `json:"name"`
			Country   string  `json:"country"`
			Admin1    string  `json:"admin1"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &geo); err != nil {
		return 0, 0, "", fmt.Errorf("geocoding parse error: %w", err)
	}
	if len(geo.Results) == 0 {
		return 0, 0, "", fmt.Errorf("找不到城市 %q", city)
	}
	r := geo.Results[0]
	label := r.Name
	if r.Admin1 != "" && r.Admin1 != r.Name {
		label = r.Admin1 + r.Name
	}
	return r.Latitude, r.Longitude, label, nil
}

// weatherCodeDesc maps a WMO weather interpretation code to a Chinese label.
func weatherCodeDesc(code int) string {
	switch code {
	case 0:
		return "晴"
	case 1:
		return "多云间晴"
	case 2:
		return "多云"
	case 3:
		return "阴"
	case 45, 48:
		return "雾"
	case 51, 53, 55:
		return "毛毛雨"
	case 56, 57:
		return "冻毛毛雨"
	case 61:
		return "小雨"
	case 63:
		return "中雨"
	case 65:
		return "大雨"
	case 66, 67:
		return "冻雨"
	case 71:
		return "小雪"
	case 73:
		return "中雪"
	case 75:
		return "大雪"
	case 77:
		return "雪粒"
	case 80:
		return "阵雨"
	case 81:
		return "强阵雨"
	case 82:
		return "暴雨"
	case 85:
		return "小阵雪"
	case 86:
		return "大阵雪"
	case 95:
		return "雷阵雨"
	case 96, 99:
		return "雷暴伴冰雹"
	default:
		return "未知天气"
	}
}

// degradedReply is used when no LLM key is configured: it tries to fetch the
// weather for the whole message treated as a city name, otherwise prompts the
// user for a city.
func (a *WeatherAgent) degradedReply(ctx context.Context, message string) string {
	city := strings.TrimSpace(message)
	if forecast, err := a.getWeather(ctx, city, 3); err == nil {
		return "（未配置模型密钥，返回原始天气数据）\n" + forecast
	}
	return "天气助手当前未配置模型密钥，暂时无法进行自然对话。请直接输入一个城市名（如：杭州）来查询天气。"
}

// --- MCP handlers (agent card / discovery compatibility) ---

func handleMCP(w http.ResponseWriter, r *http.Request) {
	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch req.Method {
	case "initialize":
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]string{
					"name":    "ati-demo-weather-agent",
					"version": "0.2.0",
				},
			},
		})

	case "tools/list":
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{
					{
						"name":        "get_weather",
						"description": "查询指定城市的天气预报",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"city": map[string]string{"type": "string", "description": "城市名称"},
							},
							"required": []string{"city"},
						},
					},
				},
			},
		})

	default:
		writeRPCError(w, req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
