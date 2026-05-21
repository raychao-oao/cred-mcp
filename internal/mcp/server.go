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
	"strings"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/clipboard"
	"github.com/raychao-oao/cred-mcp/internal/dialog"
	"github.com/raychao-oao/cred-mcp/internal/index"
	"github.com/raychao-oao/cred-mcp/internal/keychain"
	"github.com/raychao-oao/cred-mcp/internal/session"
	"github.com/raychao-oao/cred-mcp/internal/vault"
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

// defaultIndex is set by Serve and used by the stash handlers. Tests in
// the same package may override it directly.
var defaultIndex *index.Index

// defaultVault is lazily initialized on first vault tool call.
var defaultVault *vault.Client
var defaultVaultErr error

func vaultClient() (*vault.Client, error) {
	if defaultVault != nil {
		return defaultVault, nil
	}
	if defaultVaultErr != nil {
		return nil, defaultVaultErr
	}
	cfg, err := vault.DefaultConfig()
	if err != nil {
		defaultVaultErr = err
		return nil, err
	}
	c := vault.New(cfg.BaseURL, cfg.CFClientID, cfg.CFClientSecret)
	masterPassword, err := keychain.Get(cfg.MasterStashKey)
	if err != nil {
		defaultVaultErr = fmt.Errorf("master password not in keychain (stash key: %q): %w", cfg.MasterStashKey, err)
		return nil, defaultVaultErr
	}
	if err := c.Login(cfg.Email, masterPassword); err != nil {
		defaultVaultErr = fmt.Errorf("vault login failed: %w", err)
		return nil, defaultVaultErr
	}
	defaultVault = c
	log.Printf("vault: authenticated as %s", cfg.Email)
	return c, nil
}

// withVault runs fn with the vault client, automatically re-authenticating
// and retrying once if the Vaultwarden session has expired (ErrUnauthorized).
func withVault(fn func(*vault.Client) error) error {
	c, err := vaultClient()
	if err != nil {
		return err
	}
	err = fn(c)
	if !errors.Is(err, vault.ErrUnauthorized) {
		return err
	}
	log.Printf("vault: session expired, re-authenticating...")
	defaultVault = nil
	c, err = vaultClient()
	if err != nil {
		return err
	}
	return fn(c)
}

func ensureDefaultIndex() {
	if defaultIndex != nil {
		return
	}
	idx, err := index.Default()
	if err != nil {
		log.Fatalf("cred-mcp: cannot initialize index: %v", err)
	}
	defaultIndex = idx
}

// Two storage systems:
//
//	STASH — OS keychain, named slots, clipboard in/out.
//	        Use when the user copies a secret and wants AI to handle it later.
//	        Typical flow: user copies → save_stash → later copy_stash → user pastes.
//
//	VAULT — Vaultwarden (persistent credential store), searchable.
//	        Use when the user needs a saved credential by service name / username / URI.
//	        Typical flow: vault_search → vault_copy → user pastes.
//
// Secret values NEVER appear in tool responses or conversation history.
var toolsList = []map[string]any{
	{
		"name":        "ping",
		"description": "Health check — confirms cred-mcp is running. Call this if the user asks whether cred-mcp is connected, or to get the server version. No credentials are accessed.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	},
	{
		// STASH tools
		"name": "save_stash",
		"description": "STASH: Save the secret currently on the user's clipboard into a named slot in the OS keychain. " +
			"Call this when the user says they have copied a password, token, or key and wants to store it (e.g. \"save this as prod-ssh\"). " +
			"The value is read directly from the clipboard — it never enters the conversation. " +
			"The clipboard is left untouched after saving. " +
			"Overwrites any existing entry with the same name.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Short identifier for this secret (e.g. \"prod-ssh\", \"github-token\"). No colons.",
				},
			},
			"required": []string{"name"},
		},
	},
	{
		"name": "copy_stash",
		"description": "STASH: Put a previously saved secret onto the user's clipboard so they can paste it. " +
			"Call this when the user asks to retrieve a stashed secret (e.g. \"get the prod-ssh password\", \"copy github-token to clipboard\"). " +
			"If you're unsure of the exact name, call list_stash first. " +
			"The secret is placed on the clipboard for ttl_seconds, then the prior clipboard content is restored. " +
			"The value never appears in the response — only metadata (name, ttl) is returned.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name of the secret to retrieve (as given to save_stash).",
				},
				"ttl_seconds": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("How long to leave the secret on the clipboard before restoring the prior content (default %d s, max %d s).", defaultCopyTTLSeconds, maxCopyTTLSeconds),
					"minimum":     1,
					"maximum":     maxCopyTTLSeconds,
				},
			},
			"required": []string{"name"},
		},
	},
	{
		"name":        "list_stash",
		"description": "STASH: List all named secrets currently saved in the stash. Returns only metadata (name, created_at) — never values. Call this when the user asks what secrets are stored, or when you need to verify a name before calling copy_stash.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	},
	{
		"name":        "delete_stash",
		"description": "STASH: Permanently delete a named secret from the stash. Call when the user asks to remove or clean up a stored secret.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name of the secret to delete.",
				},
			},
			"required": []string{"name"},
		},
	},
	{
		// VAULT tools
		"name": "vault_search",
		"description": "VAULT: Search the Vaultwarden credential vault and return matching login items. " +
			"Call this first whenever the user needs a saved credential — e.g. \"get the password for asablue\", \"find the router login\". " +
			"Matches case-insensitively against item name, username, and URI. " +
			"Returns metadata only (id, name, username, URIs) — never passwords. " +
			"Use the returned id with vault_copy to put the password on the clipboard.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "Substring to search for (name, username, or URI). Use empty string to list all items.",
				},
			},
			"required": []string{"query"},
		},
	},
	{
		"name": "vault_copy",
		"description": "VAULT: Copy a vault item's password to the clipboard. " +
			"Always call vault_search first to find the item and get its id. " +
			"The password is placed on the clipboard for ttl_seconds — tell the user to paste now. " +
			"The password never enters the conversation; only metadata is returned.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id": map[string]any{
					"type":        "string",
					"description": "Item ID from vault_search.",
				},
				"ttl_seconds": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Seconds before clipboard is restored (default %d, max %d).", defaultCopyTTLSeconds, maxCopyTTLSeconds),
					"minimum":     1,
					"maximum":     maxCopyTTLSeconds,
				},
			},
			"required": []string{"id"},
		},
	},
	{
		"name": "vault_add",
		"description": "VAULT: Add a new login item to the vault. " +
			"Call this when the user wants to permanently save new credentials (e.g. \"add the new router password to the vault\"). " +
			"The password is entered via a native GUI dialog (default) or read from the clipboard — it never comes from the conversation. " +
			"Returns the new item's id and metadata.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Display name for the item (e.g. \"prod-router\", \"GitHub raychao-oao\").",
				},
				"username": map[string]any{
					"type":        "string",
					"description": "Username or account identifier. Omit or pass empty string if not applicable.",
				},
				"uris": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Optional list of hostnames or URLs for this credential (helps vault_search find it later).",
				},
				"password_source": map[string]any{
					"type":        "string",
					"enum":        []string{"dialog", "clipboard"},
					"description": "\"dialog\" (default): a native GUI prompt appears for the user to type the password. \"clipboard\": the password is read from the current clipboard.",
				},
			},
			"required": []string{"name"},
		},
	},
	{
		"name": "vault_update",
		"description": "VAULT: Update an existing vault item's name, username, URIs, or password. " +
			"Call vault_search first to find the item id. " +
			"Omit any field to leave it unchanged. " +
			"Set update_password=true to replace the password — it will be sourced via GUI dialog or clipboard, never from the conversation.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id": map[string]any{
					"type":        "string",
					"description": "Item ID from vault_search.",
				},
				"name": map[string]any{
					"type":        "string",
					"description": "New display name. Omit to keep existing.",
				},
				"username": map[string]any{
					"type":        "string",
					"description": "New username. Omit to keep existing.",
				},
				"uris": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Replacement URI list. Omit to keep existing.",
				},
				"update_password": map[string]any{
					"type":        "boolean",
					"description": "If true, replace the password (sourced via password_source).",
				},
				"password_source": map[string]any{
					"type":        "string",
					"enum":        []string{"dialog", "clipboard"},
					"description": "How to obtain the new password when update_password=true. \"dialog\" (default) pops a native GUI input; \"clipboard\" reads the current clipboard.",
				},
			},
			"required": []string{"id"},
		},
	},
	{
		// SEALED CREDENTIAL tools (AI-native PAM protocol)
		"name": "request_authorization",
		"description": "SEALED: Request biometric authorization for a consumer MCP to access a vault item. " +
			"Call this before vault_seal when a consumer MCP (e.g. pty-mcp, imap-mcp) needs a credential delivered securely. " +
			"If the registry requires it, triggers a biometric prompt (Touch ID / Windows Hello) on the user's device. " +
			"Returns a single-use auth_token valid for ttl_seconds. " +
			"The token is not a secret — it is bound to (item_id, consumer_id, purpose) and useless without the matching vault_seal call.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"item_id": map[string]any{
					"type":        "string",
					"description": "Vault item ID (from vault_search) to authorize access to.",
				},
				"consumer_id": map[string]any{
					"type":        "string",
					"description": "Registered consumer MCP ID (e.g. \"pty-mcp\", \"imap-mcp\").",
				},
				"purpose": map[string]any{
					"type":        "string",
					"description": "Short label describing why the credential is needed (e.g. \"ssh-login\", \"imap-login\"). Must match an allowed_purpose in the registry.",
				},
				"ttl_seconds": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("How long the auth token stays valid (default %d s, max %d s).", defaultAuthzTTLSeconds, maxAuthzTTLSeconds),
					"minimum":     1,
					"maximum":     maxAuthzTTLSeconds,
				},
			},
			"required": []string{"item_id", "consumer_id", "purpose"},
		},
	},
	{
		"name": "vault_seal",
		"description": "SEALED: Encrypt a vault item's secret directly into a consumer MCP's session key using HPKE. " +
			"The AI carries only opaque ciphertext — the plaintext never enters the LLM context. " +
			"Call request_authorization first to obtain auth_token. " +
			"Call the consumer MCP's get_credential_bundle tool to get consumer_bundle. " +
			"Returns a sealed_box that the consumer MCP decrypts autonomously via its SDK.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"item_id": map[string]any{
					"type":        "string",
					"description": "Vault item ID to seal (same as used in request_authorization).",
				},
				"consumer_bundle": map[string]any{
					"type":        "object",
					"description": "ConsumerBundle JSON from the consumer MCP's get_credential_bundle tool.",
				},
				"auth_token": map[string]any{
					"type":        "string",
					"description": "Single-use token from request_authorization.",
				},
				"purpose": map[string]any{
					"type":        "string",
					"description": "Purpose label — must match the value used in request_authorization.",
				},
				"box_ttl_seconds": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("How long the sealed box stays valid (default %d s, max %d s).", defaultBoxTTLSeconds, maxBoxTTLSeconds),
					"minimum":     1,
					"maximum":     maxBoxTTLSeconds,
				},
			},
			"required": []string{"item_id", "consumer_bundle", "auth_token", "purpose"},
		},
	},
}

// Serve runs the JSON-RPC stdio loop. version is reported via initialize.
func Serve(version string) {
	ensureDefaultIndex()

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

	// ping is a health check and never touches secrets, so it bypasses
	// the session gate. Every other tool MUST go through it; the dispatch
	// here is the single chokepoint so a future tool can't accidentally
	// skip authorization by forgetting to call session.Default.Touch.
	if p.Name != "ping" {
		if err := session.Default.Touch(); err != nil {
			log.Printf("tools/call %s denied: %v", p.Name, err)
			return toolErrResp(req.ID, fmt.Sprintf("%v", err))
		}
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
	case "list_stash":
		return handleListStash(req.ID, p.Arguments)
	case "vault_search":
		return handleVaultSearch(req.ID, p.Arguments)
	case "vault_add":
		return handleVaultAdd(req.ID, p.Arguments)
	case "vault_update":
		return handleVaultUpdate(req.ID, p.Arguments)
	case "vault_copy":
		return handleVaultCopy(req.ID, p.Arguments)
	case "request_authorization":
		return handleRequestAuthorization(req.ID, p.Arguments)
	case "vault_seal":
		return handleVaultSeal(req.ID, p.Arguments)
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

	// Track the name in the index. Failure here is logged but does not
	// fail save_stash — the secret is genuinely stored and that is what
	// the AI should know. Index drift can be repaired by re-running
	// save_stash (Add is idempotent) or via list_stash inspection.
	if err := defaultIndex.Add(args.Name, index.SourceKeychain); err != nil {
		log.Printf("save_stash: index Add failed for %q (re-run to repair tracking): %v", args.Name, err)
	}

	// The clipboard is intentionally left alone. The user put the secret
	// there knowingly; trying to clear it racily on every OS pasteboard
	// produces TOCTOU bugs and offers little real protection (clipboard
	// managers keep history anyway). Lifetime of AI access to the stored
	// secret is governed by session expiry, not by clipboard manipulation.
	return okResp(id, map[string]any{
		"name":   args.Name,
		"status": "stored",
		"note":   "Secret stored. Clipboard left alone — manage it yourself.",
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
			// Even when the keychain entry is missing, sweep the index in
			// case it is the side that is stale. Idempotent.
			if rmErr := defaultIndex.Remove(args.Name, index.SourceKeychain); rmErr != nil {
				log.Printf("delete_stash: index Remove failed for %q: %v", args.Name, rmErr)
			}
			return toolErrResp(id, fmt.Sprintf("no stored secret named %q", args.Name))
		}
		return toolErrResp(id, fmt.Sprintf("keychain error: %v", err))
	}

	if err := defaultIndex.Remove(args.Name, index.SourceKeychain); err != nil {
		log.Printf("delete_stash: index Remove failed for %q: %v", args.Name, err)
	}

	return okResp(id, map[string]any{
		"name":   args.Name,
		"status": "deleted",
	})
}

func handleListStash(id any, _ json.RawMessage) response {
	entries, err := defaultIndex.List()
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("index error: %v", err))
	}

	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"name":       e.Name,
			"source":     string(e.Source),
			"created_at": e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return okResp(id, map[string]any{
		"count":   len(entries),
		"entries": out,
	})
}

type vaultSearchArgs struct {
	Query string `json:"query"`
}

func handleVaultSearch(id any, raw json.RawMessage) response {
	var args vaultSearchArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}

	var items []vault.Item
	if err := withVault(func(vc *vault.Client) error {
		var e error
		items, e = vc.Search(args.Query)
		return e
	}); err != nil {
		return toolErrResp(id, fmt.Sprintf("vault search: %v", err))
	}

	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"id":       it.ID,
			"name":     it.Name,
			"username": it.Username,
			"uris":     it.URIs,
		})
	}
	return okResp(id, map[string]any{
		"count": len(items),
		"items": out,
	})
}

// readPassword obtains a secret via dialog (default) or clipboard.
// source="" or "dialog" → native GUI prompt; "clipboard" → current clipboard.
// Any other value is rejected.
func readPassword(source, prompt string) (string, error) {
	switch source {
	case "", "dialog":
		val, err := dialog.ReadSecret(prompt)
		if err != nil {
			return "", fmt.Errorf("dialog error: %v", err)
		}
		if val == "" {
			return "", fmt.Errorf("no password entered")
		}
		return val, nil
	case "clipboard":
		val, err := clipboard.Read()
		if err != nil {
			return "", fmt.Errorf("clipboard error: %v", err)
		}
		if val == "" {
			return "", fmt.Errorf("clipboard is empty — ask the user to copy the password first")
		}
		return val, nil
	default:
		return "", fmt.Errorf("unknown password_source %q: must be \"dialog\" or \"clipboard\"", source)
	}
}

type vaultAddArgs struct {
	Name           string   `json:"name"`
	Username       string   `json:"username"`
	URIs           []string `json:"uris"`
	PasswordSource string   `json:"password_source"`
}

func handleVaultAdd(id any, raw json.RawMessage) response {
	var args vaultAddArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if strings.TrimSpace(args.Name) == "" {
		return toolErrResp(id, "name is required")
	}
	if args.PasswordSource == "" {
		args.PasswordSource = "dialog"
	}

	password, err := readPassword(args.PasswordSource, fmt.Sprintf("Password for %q", args.Name))
	if err != nil {
		return toolErrResp(id, err.Error())
	}

	var newID string
	if err := withVault(func(vc *vault.Client) error {
		var e error
		newID, e = vc.Add(args.Name, args.Username, password, args.URIs)
		return e
	}); err != nil {
		return toolErrResp(id, fmt.Sprintf("vault add: %v", err))
	}

	return okResp(id, map[string]any{
		"id":              newID,
		"name":            args.Name,
		"username":        args.Username,
		"uris":            args.URIs,
		"status":          "created",
		"note":            "Password stored encrypted. It never entered the conversation.",
		"password_source": args.PasswordSource,
	})
}

type vaultUpdateArgs struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Username       string   `json:"username"`
	URIs           []string `json:"uris"`
	UpdatePassword bool     `json:"update_password"`
	PasswordSource string   `json:"password_source"`
}

func handleVaultUpdate(id any, raw json.RawMessage) response {
	var args vaultUpdateArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if strings.TrimSpace(args.ID) == "" {
		return toolErrResp(id, "id is required")
	}

	var password string
	if args.UpdatePassword {
		var err error
		password, err = readPassword(args.PasswordSource, fmt.Sprintf("New password for item %q", args.ID))
		if err != nil {
			return toolErrResp(id, err.Error())
		}
	}

	updateURIs := args.URIs != nil
	if err := withVault(func(vc *vault.Client) error {
		return vc.Update(args.ID, args.Name, args.Username, password, args.URIs, updateURIs)
	}); err != nil {
		return toolErrResp(id, fmt.Sprintf("vault update: %v", err))
	}

	updated := []string{}
	if args.Name != "" {
		updated = append(updated, "name")
	}
	if args.Username != "" {
		updated = append(updated, "username")
	}
	if updateURIs {
		updated = append(updated, "uris")
	}
	if args.UpdatePassword {
		updated = append(updated, "password")
	}

	return okResp(id, map[string]any{
		"id":      args.ID,
		"updated": updated,
		"status":  "updated",
	})
}

type vaultCopyArgs struct {
	ID         string `json:"id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func handleVaultCopy(id any, raw json.RawMessage) response {
	var args vaultCopyArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
		}
	}
	if strings.TrimSpace(args.ID) == "" {
		return toolErrResp(id, "id is required")
	}
	ttlSeconds := args.TTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = defaultCopyTTLSeconds
	}
	if ttlSeconds > maxCopyTTLSeconds {
		ttlSeconds = maxCopyTTLSeconds
	}

	var secret string
	if err := withVault(func(vc *vault.Client) error {
		var e error
		secret, e = vc.Secret(args.ID)
		return e
	}); err != nil {
		return toolErrResp(id, fmt.Sprintf("vault get secret: %v", err))
	}

	ttl := time.Duration(ttlSeconds) * time.Second
	wait, err := clipboard.SetWithAutoClear(context.Background(), secret, ttl)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("clipboard error: %v", err))
	}
	go func() {
		result := wait()
		log.Printf("vault_copy id=%q ttl=%s result=%s", args.ID, ttl, result)
	}()

	return okResp(id, map[string]any{
		"id":          args.ID,
		"ttl_seconds": ttlSeconds,
		"status":      "copied",
		"note":        "Password is on the clipboard. It will be restored after the TTL.",
	})
}
