package jsonrpc

import "encoding/json"

const Version = "2.0"

// Standard error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

func IsNotification(req *Request) bool {
	return len(req.ID) == 0 || string(req.ID) == "null"
}

func NewResponse(id json.RawMessage, result any) *Response {
	return &Response{JSONRPC: Version, ID: id, Result: result}
}

func NewErrorResponse(id json.RawMessage, code int, msg string) *Response {
	return &Response{JSONRPC: Version, ID: id, Error: &Error{Code: code, Message: msg}}
}

func Parse(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	if req.JSONRPC != Version {
		return nil, &Error{Code: CodeInvalidRequest, Message: "invalid jsonrpc version"}
	}
	return &req, nil
}
