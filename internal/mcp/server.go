package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/clipboard"
	"github.com/raychao-oao/cred-mcp/internal/keychain"
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

// Default and ceiling values for copy_stash auto-clear TTL.
const (
	defaultCopyTTLSeconds = 30
	maxCopyTTLSeconds     = 600
)

var toolsList = []map[string]any{
	{
		"name":        "ping",
		"description": "Health check. Returns server version and current time. Used to verify cred-mcp is reachable; no credentials are accessed.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	},
	{
		"name": "copy_stash",
		"description": "Copy a stored secret to the user's clipboard for a limited time. " +
			"The secret value never enters the conversation; only metadata (name, ttl) is returned. " +
			"After the TTL expires the clipboard is restored to its prior contents " +
			"(unless the user has pasted-and-replaced it in the meantime).",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Identifier of the stored secret (no colons).",
				},
				"ttl_seconds": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Seconds before the clipboard is restored (default %d, max %d).", defaultCopyTTLSeconds, maxCopyTTLSeconds),
					"minimum":     1,
					"maximum":     maxCopyTTLSeconds,
				},
			},
			"required": []string{"name"},
		},
	},
	{
		"name": "save_stash",
		"description": "Store the secret currently on the user's clipboard under the given name. " +
			"The secret value never enters the conversation: it is read directly from the clipboard, " +
			"written to the OS keychain, and the clipboard is then cleared. " +
			"Use this when the user has just copied a password/token they want stashed for later retrieval. " +
			"Overwrites any existing entry with the same name.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Identifier to store the secret under (no colons, must not be empty).",
				},
			},
			"required": []string{"name"},
		},
	},
	{
		"name": "delete_stash",
		"description": "Delete a stored secret by name. Returns an error if no entry exists with that name.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Identifier of the stored secret to delete (no colons).",
				},
			},
			"required": []string{"name"},
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
	case "copy_stash":
		return handleCopyStash(req.ID, p.Arguments)
	case "save_stash":
		return handleSaveStash(req.ID, p.Arguments)
	case "delete_stash":
		return handleDeleteStash(req.ID, p.Arguments)
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

// toolErrResp returns a tool-call response with isError=true so MCP clients
// can surface the failure without treating it as a JSON-RPC protocol error.
func toolErrResp(id any, msg string) response {
	return response{JSONRPC: "2.0", ID: id, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}}
}

func errResp(id any, code int, msg string) response {
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

type copyStashArgs struct {
	Name       string `json:"name"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func handleCopyStash(id any, raw json.RawMessage) response {
	var args copyStashArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if args.Name == "" {
		return toolErrResp(id, "name is required")
	}
	ttlSeconds := args.TTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = defaultCopyTTLSeconds
	}
	if ttlSeconds > maxCopyTTLSeconds {
		ttlSeconds = maxCopyTTLSeconds
	}

	value, err := keychain.Get(args.Name)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return toolErrResp(id, fmt.Sprintf("no stored secret named %q", args.Name))
		}
		return toolErrResp(id, fmt.Sprintf("keychain error: %v", err))
	}

	ttl := time.Duration(ttlSeconds) * time.Second
	wait, err := clipboard.SetWithAutoClear(context.Background(), value, ttl)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("clipboard error: %v", err))
	}

	// Auto-clear runs in the background; the tool call returns immediately.
	go func() {
		result := wait()
		log.Printf("copy_stash name=%q ttl=%s result=%s", args.Name, ttl, result)
	}()

	// Deliberately omit the secret value from the response.
	return okResp(id, map[string]any{
		"name":        args.Name,
		"ttl_seconds": ttlSeconds,
		"status":      "copied",
		"note":        "Secret is on the clipboard. It will be restored to the prior value after the TTL unless the user pastes-and-replaces it.",
	})
}

type saveStashArgs struct {
	Name string `json:"name"`
}

func handleSaveStash(id any, raw json.RawMessage) response {
	var args saveStashArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if args.Name == "" {
		return toolErrResp(id, "name is required")
	}

	value, err := clipboard.Read()
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("clipboard error: %v", err))
	}
	if value == "" {
		return toolErrResp(id, "clipboard is empty; ask the user to copy the secret first")
	}

	if err := keychain.Set(args.Name, value); err != nil {
		return toolErrResp(id, fmt.Sprintf("keychain error: %v", err))
	}

	// Clear the clipboard so the plaintext does not linger after stashing.
	if err := clipboard.Clear(); err != nil {
		log.Printf("save_stash: clipboard clear failed: %v", err)
	}

	return okResp(id, map[string]any{
		"name":   args.Name,
		"status": "stored",
		"note":   "Secret stored. Clipboard cleared.",
	})
}

type deleteStashArgs struct {
	Name string `json:"name"`
}

func handleDeleteStash(id any, raw json.RawMessage) response {
	var args deleteStashArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if args.Name == "" {
		return toolErrResp(id, "name is required")
	}

	if err := keychain.Delete(args.Name); err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return toolErrResp(id, fmt.Sprintf("no stored secret named %q", args.Name))
		}
		return toolErrResp(id, fmt.Sprintf("keychain error: %v", err))
	}

	return okResp(id, map[string]any{
		"name":   args.Name,
		"status": "deleted",
	})
}
