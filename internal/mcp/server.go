package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

var toolsList = []map[string]any{
	{
		"name":        "ping",
		"description": "Health check. Returns server version and current time. Used to verify cred-mcp is reachable; no credentials are accessed.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	},
}

// Serve runs the JSON-RPC stdio loop. version is reported via initialize.
func Serve(version string) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	log.SetOutput(os.Stderr)
	log.Printf("cred-mcp server started (version=%s)", version)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("parse error: %v", err)
			continue
		}
		resp := handle(&req, version)
		if resp.ID == nil && resp.Result == nil && resp.Error == nil {
			continue
		}
		if err := encoder.Encode(resp); err != nil {
			log.Printf("encode error: %v", err)
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Printf("stdin error: %v", err)
	}
}

func handle(req *request, version string) response {
	switch req.Method {
	case "initialize":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "cred-mcp", "version": version},
		}}
	case "tools/list":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": toolsList}}
	case "tools/call":
		return handleToolCall(req, version)
	case "notifications/initialized", "$/cancelRequest":
		return response{}
	default:
		return errResp(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func handleToolCall(req *request, version string) response {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, -32602, err.Error())
	}

	switch p.Name {
	case "ping":
		return okResp(req.ID, map[string]any{
			"ok":      true,
			"version": version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	default:
		return errResp(req.ID, -32601, fmt.Sprintf("unknown tool: %s", p.Name))
	}
}

func okResp(id any, result any) response {
	b, _ := json.MarshalIndent(result, "", "  ")
	return response{JSONRPC: "2.0", ID: id, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
	}}
}

func errResp(id any, code int, msg string) response {
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
