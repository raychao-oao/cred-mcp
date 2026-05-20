---
name: cred-mcp
description: This skill should be used when needing credentials, passwords, API keys, or tokens for any task; when the user asks to "search vault", "copy password", "save token", "store secret", "look up credentials", "find the password for", "put credentials in clipboard"; or when Claude detects it needs authentication material to complete a task (SSH login, API call, service configuration). Provides secure credential access via OS keychain and Vaultwarden without exposing plaintext to LLM context.
version: 0.1.0
---

# cred-mcp — Secure Credential Access

cred-mcp bridges Vaultwarden (cloud vault) and OS keychain with AI workflows. Credentials reach the user or downstream tools via clipboard — never as plaintext in LLM context.

**MCP server**: `plugin:cred-mcp:cred-mcp` (production) · `plugin:cred-mcp-dev:cred-mcp` (dev build)

## Tools

| Tool | What it does |
|------|-------------|
| `vault_search` | Search Vaultwarden items by name, username, or URI |
| `vault_copy` | Copy a vault item field (password/totp/notes) to clipboard |
| `vault_add` | Add a new item to Vaultwarden |
| `vault_update` | Update an existing vault item |
| `save_stash` | Read clipboard → store in OS keychain (for temporary secrets) |
| `copy_stash` | Retrieve from OS keychain → put in clipboard (auto-clears in 30s) |
| `list_stash` | List all stash entries (metadata only, no values) |
| `delete_stash` | Remove a stash entry from keychain |
| `ping` | Health check — verify cred-mcp is running |

## Tool Selection

**Need a credential from Vaultwarden?**
1. `vault_search` — find the item
2. `vault_copy` — put the field in clipboard

**Need to store a temporary secret (token, API key)?**
1. Ask user to copy it to clipboard
2. `save_stash` — reads clipboard, stores in OS keychain

**Need to retrieve a stored stash?**
1. `copy_stash` — puts value in clipboard (auto-clears in 30s)

**Need to create a new vault entry?**
1. `vault_add` with `password_source: "clipboard"` (user copies password first) or `"generate"` (auto-generate)

## Security Constraints

These rules are non-negotiable:

- **Never return raw passwords, tokens, or TOTP codes in tool results.** Vault values flow to clipboard only.
- **Never use `pbpaste` or bash to read clipboard contents** — that puts the secret into LLM context.
- **Never ask the user to type a password in chat.** Use clipboard + Cmd+V paste instead.
- **Username, item names, URIs, and other non-secret metadata** may appear in tool results and conversation.
- **`send_secret`** is the right tool when a PTY session is waiting for password input — not `copy_stash` + send_input.

## Common Patterns

### Find a service credential and use it

```
vault_search(query: "asablue")
→ returns item list with names, usernames, IDs

vault_copy(item_id: "...", field: "password")
→ password now in clipboard; user pastes with Cmd+V
```

### Store a temporary API key

```
# User copies API key to clipboard first
save_stash(name: "openai-key")
→ key stored in OS keychain under name "openai-key"

# Later, retrieve it
copy_stash(name: "openai-key")
→ key in clipboard for 30s, then auto-cleared
```

### SSH login with vault credential + pty-mcp

```
vault_search(query: "asablue ssh")
vault_copy(item_id: "...", field: "password")
# password now in clipboard

create_ssh_session(host: "asablue", user: "jcchao")
# when session prompts for password:
send_secret(session_id: "...", prompt: "SSH password:")
# GUI dialog appears — user pastes from clipboard, AI never sees value
```

### Add a new credential

```
# Option A: user copies password to clipboard first
vault_add(name: "New Service", username: "admin", uri: "https://...", password_source: "clipboard")

# Option B: generate a strong password
vault_add(name: "New Service", username: "admin", uri: "https://...", password_source: "generate")
```

## Session Behavior

cred-mcp maintains a session with sliding TTL (idle 30 min / absolute 8 hr). When the session expires:
- v0.3.2+: Vaultwarden 401 triggers automatic re-authentication — no manual action needed.
- The first vault tool call after expiry will re-authenticate transparently.

Check health with `ping` — returns `{"ok": true, "version": "vX.Y.Z"}`.

## Additional Resources

- **`references/patterns.md`** — Extended workflow patterns, error handling, vault folder structure, pty-mcp integration details
