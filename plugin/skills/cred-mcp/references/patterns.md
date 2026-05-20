# cred-mcp Extended Patterns

## Vault Search Tips

`vault_search` matches against item name, username, and URI. Use short keywords:

```
vault_search(query: "asablue")      # finds "asablue SSH", "asablue sudo", etc.
vault_search(query: "cloudflare")   # finds all CF-related items
vault_search(query: "ray@")         # find by username fragment
```

Results include: `id`, `name`, `username`, `uri` — never the password.

## Field Selection for vault_copy

| field value | What it copies |
|-------------|---------------|
| `"password"` | Login password (default) |
| `"totp"` | Current TOTP code (time-based, use immediately) |
| `"notes"` | Secure notes field |
| `"username"` | Username (not sensitive, but convenient) |

TOTP codes expire in ~30s. Copy and use immediately.

## Stash vs Vault

| | Stash (OS keychain) | Vault (Vaultwarden) |
|---|---|---|
| **Scope** | Local device only | Synced across devices |
| **Best for** | Temporary tokens, session keys | Persistent credentials |
| **Retrieval** | `copy_stash` by name | `vault_search` → `vault_copy` |
| **Auto-clear** | 30s after `copy_stash` | Never (user manages) |
| **Survives restart** | Yes (OS keychain persists) | Yes |

## pty-mcp Integration

### Pattern: SSH with vault password

```
# 1. Find and stage credential
vault_search(query: "hostname ssh")
vault_copy(item_id: "abc123", field: "password")
# clipboard now has password

# 2. Open SSH session
create_ssh_session(host: "hostname", user: "admin")
read_output(session_id, wait_for: "password|\\$|#")

# 3. If password prompt detected, use send_secret
# send_secret shows a GUI dialog — user pastes from clipboard
# AI never sees the password
send_secret(session_id, prompt: "SSH password (paste from clipboard):")
read_output(session_id, wait_for: "\\$|#", timeout: 15)
```

### Pattern: sudo with stash

```
# User has already stash-saved sudo password as "sudo-asablue"
create_ssh_session(host: "asablue", user: "jcchao")
send_input(session_id, "sudo systemctl restart nginx")
read_output(session_id, wait_for: "password")

copy_stash(name: "sudo-asablue")
# password in clipboard for 30s
send_secret(session_id, prompt: "sudo password (paste from clipboard):")
```

### When NOT to use send_secret

`send_secret` opens a GUI dialog and waits for keyboard input. Only call it when the PTY session is actively waiting at a password prompt (echo-off mode). Do not call it on an idle shell prompt — it will block indefinitely.

## Error Handling

### Item not found

```
vault_search returns empty list
→ Inform user: "No vault item found matching 'X'. 
   Options: vault_add to create it, or ask user to copy credential to clipboard then save_stash."
```

### Vault 401 (session expired)

v0.3.2+ handles this automatically via `withVault()` retry. If a vault tool returns an auth error on older versions, the user needs to restart the cred-mcp process (restart Claude Code).

### Stash name not found

```
copy_stash returns error "not found"
→ Check list_stash for available entries.
   If missing, ask user to copy the secret to clipboard and save_stash under the expected name.
```

### cred-mcp not running

```
ping fails / tool not available
→ Check: claude mcp list
   If offline: restart Claude Code, or check plugin installation with:
   claude plugin list | grep cred-mcp
```

## vault_add Password Sources

| source | Behavior |
|--------|---------|
| `"clipboard"` | Reads current clipboard — user must copy password first |
| `"generate"` | Auto-generates a strong random password |
| `"prompt"` | Opens a secure OS dialog — user types directly (never in chat) |

Always confirm with user which source to use before calling `vault_add`.

## vault_update Empty-Field Semantics

When updating a vault item, omit fields that should remain unchanged. Passing an empty string `""` may overwrite the existing value with blank — leave the parameter absent instead.
