# cred-mcp

> Credential management MCP server for AI agents — store secrets in your OS keychain, hand them to AI workflows without ever putting plaintext into the LLM context.

**Status**: `v0.4.1` — Stash, vault, and AI-native PAM protocol tools are stable. Biometric re-unlock (Touch ID / Windows Hello gating) is deferred to a future release.

## What it does

`cred-mcp` is a stdio MCP server. AI agents (Claude Code et al.) call its tools to **stash** and **retrieve** secrets. The plaintext value never appears in the conversation: `save_stash` reads it from your clipboard, `copy_stash` writes it back to your clipboard with a TTL.

```
You copy a password    →    You ask AI: "save it as prod-ssh"
                            AI calls save_stash{name: "prod-ssh"}
                            cred-mcp reads clipboard, writes OS keychain
                            (response carries only the name; LLM never sees the value)

Later, you ask AI: "I'm SSHing into prod, get me the password"
                            AI calls copy_stash{name: "prod-ssh"}
                            cred-mcp pulls from keychain, puts on clipboard for 30s
                            (response carries only metadata; LLM never sees the value)
You paste into the SSH prompt; clipboard auto-restores after the TTL.
```

## AI-native credential delivery (v0.4.0)

The PAM protocol lets cred-mcp hand a vault secret directly to a consumer MCP (e.g. pty-mcp) **without the plaintext ever passing through the AI**. The AI acts as an untrusted courier carrying only public keys and ciphertext.

```
pty-mcp.get_credential_bundle()  →  ConsumerBundle (public keys only, safe for AI)
cred-mcp.request_authorization() →  auth_token (single-use, binds item + consumer + purpose)
cred-mcp.vault_seal(bundle, auth_token) → SealedBox (HPKE ciphertext)
pty-mcp.inject_secret(sealed_box) → decrypt → write to PTY → zeroize memory
```

The consumer (pty-mcp) holds the private session key; cred-mcp never sees it. cred-mcp encrypts with the consumer's ephemeral X25519 public key so only that specific session can decrypt. Plaintext never enters any log, response, or LLM context.

### Consumer registry setup

`request_authorization` and `vault_seal` check a YAML registry to verify that the consumer is known and allowed to request the given item and purpose.

**Step 1 — get the consumer's identity key**

Ask the AI to run `get_credential_bundle` on pty-mcp, then convert the `identity_pub_key` field from base64 to hex:

```bash
echo "<identity_pub_key from bundle>" | base64 -d | xxd -p | tr -d '\n'
```

**Step 2 — create the registry file**

Copy `registry.yaml.example` from the repo to `~/.config/cred-mcp/registry.yaml` (or set `CRED_MCP_REGISTRY` to a custom path) and fill in the hex key:

```yaml
consumers:
  pty-mcp:
    identity_pub_key: "b519ada7..."   # hex from step 1
    allowed_items:
      - "*"                           # or list specific vault item UUIDs
    allowed_purposes:
      - "ssh-login"
    approval_mode: auto               # "auto" or "required" (biometric)
```

**Step 3 — verify**

The registry is loaded on first use and cached in memory. If cred-mcp was already running when you created the file, the next tool call will pick it up automatically — no restart needed. If you **update** an existing registry file, restart cred-mcp to reload it (`pkill -f cred-mcp`; Claude Code re-launches it automatically).

## Tools (`v0.4.1`)

| Tool | Purpose |
|------|---------|
| `ping` | Health check. Returns server version + current time. |
| `save_stash` | Read user's clipboard, store under `name` in OS keychain. Clipboard is left untouched after — manage it as your normal workflow. |
| `copy_stash` | Read stored secret by `name`, put on clipboard for `ttl_seconds` (default 30, max 600). Auto-restores prior clipboard contents after the TTL unless the user has paste-and-replaced it. |
| `delete_stash` | Remove a stored secret by `name`. |
| `list_stash` | List metadata for all stored secrets (`name`, `source`, `created_at`). Values are never returned. Useful for migration: see what has already been moved into safe storage. |
| `vault_search` | Search your Vaultwarden vault by name, username, or URI. Returns item metadata (never passwords). |
| `vault_copy` | Copy a vault item's login password to the clipboard with a TTL. |
| `vault_add` | Add a new login item to the vault. Password sourced via `"dialog"` (native GUI, default) or `"clipboard"` — never via the chat. |
| `vault_update` | Update fields on an existing vault item (name, username, URIs). Password update uses the same `"dialog"` / `"clipboard"` sources as `vault_add`. |
| `request_authorization` | Check consumer registry ACL and issue a single-use auth token bound to `(item_id, consumer_id, purpose)`. Triggers biometric prompt if `approval_mode: required`. |
| `vault_seal` | Verify the consumer bundle, consume the auth token, fetch plaintext from vault, HPKE-encrypt it for the consumer's session key, return a `SealedBox`. Plaintext never leaves cred-mcp. |

All tools that touch secrets return only metadata (`name`, `status`, `note`, `ttl_seconds`, `source`, `created_at`). The value is never serialized into the response or stderr logs.

`list_stash` is backed by an index file at the OS user config directory:

```
macOS:    ~/Library/Application Support/cred-mcp/index.json
Linux:    $XDG_CONFIG_HOME/cred-mcp/index.json (or ~/.config/...)
Windows:  %AppData%\cred-mcp\index.json
```

The index stores names only (no values). It is `chmod 0600`. You can inspect it with `cat`; you can also delete it to start fresh, with the only loss being the names you already had — the keychain entries themselves are unaffected.

## Build & install

Requires Go 1.22+ and a desktop OS keychain (macOS Keychain / Windows Credential Manager / Linux Secret Service).

```bash
git clone https://github.com/raychao-oao/cred-mcp.git
cd cred-mcp
make build         # produces ./cred-mcp
./cred-mcp --version
```

For Claude Code dev install (using the local `cred-mcp-dev` plugin):

```bash
make install-dev   # copies binary into ~/.claude/plugins/local/cred-mcp-dev/bin/
# Restart Claude Code to pick up the new binary.
```

## Dev CLI subcommands (manual inspection only)

These never go over MCP; they exist for setup, debugging, and seeding test entries:

```bash
cred-mcp dev keychain set <name>     # read value from stdin, store
cred-mcp dev keychain get <name>     # print value to stdout
cred-mcp dev keychain del <name>     # delete

cred-mcp dev clipboard set [-ttl 30s]  # set clipboard from stdin, optional auto-restore
cred-mcp dev clipboard clear           # clear clipboard

cred-mcp dev biometric test            # fire a biometric prompt and report outcome
```

Plaintext is read from stdin, never from argv (no shell history leak).

## Security model & known gaps

- **Plaintext never enters LLM context.** Tool responses and stderr logs carry only metadata (`name`, `status`, `note`, `ttl_seconds`). The clipboard is the side channel for the human user.
- **Biometric / passcode gating** (macOS only currently). The first secret-touching tool call after process start prompts Touch ID via `LAPolicyDeviceOwnerAuthentication` — Touch ID failure / absence falls back to the system password automatically. The prompt is OS-mediated and does not require a Cocoa event loop, so it works for a stdio-based MCP server. **Windows / Linux are not yet implemented**: those builds compile against a stub that grants unlock without prompting (effectively the pre-feat/biometric AutoUnlock policy). Per-platform support will land in follow-up branches; until then, only macOS gets a real challenge.
- **Session expiry: idle 30 min / absolute 8 hr.** The first secret-touching tool call after process start triggers the unlock prompt; activity refreshes the idle timer. Once either TTL fires, the session enters Expired state — the next call re-runs the unlock policy (Touch ID / passcode prompt). On success, the session resumes with fresh timers. On user cancel / decline, the call is denied and state stays Expired (subsequent calls re-prompt). `ping` always bypasses the gate (health check). State does not persist across restarts.
- **Vault integration** (Vaultwarden / Bitwarden). `vault_search` and `vault_copy` connect to a self-hosted Vaultwarden instance. The master password is pulled from the OS keychain (never typed into the chat). Configure via environment variables in your `.mcp.json`:

  | Variable | Purpose |
  |----------|---------|
  | `CRED_MCP_VAULT_URL` | Vaultwarden base URL |
  | `CRED_MCP_VAULT_EMAIL` | Vaultwarden account email |
  | `CRED_MCP_VAULT_CF_CLIENT_ID` | Cloudflare Access client ID (if vault is behind CF Access) |
  | `CRED_MCP_VAULT_CF_CLIENT_SECRET` | Cloudflare Access client secret |
  | `CRED_MCP_VAULT_MASTER_STASH_KEY` | Keychain key holding the master password (default: `vaultwarden-master`) |

  Legacy `VAULTWARDEN_*` names are accepted as fallbacks for backward compatibility.
- **Cross-device sync is out of scope.** Each device's keychain is independent — this is intentional, not a bug. Vaultwarden handles human-side sync; cred-mcp handles per-device AI-side access.

## Plugin packaging

Two parallel packages, mirroring the `pty-mcp` / `pty-mcp-dev` split:

| Package | Source | Purpose |
|---------|--------|---------|
| `cred-mcp` | GitHub release | End-user install via Claude Code marketplace |
| `cred-mcp-dev` | Local directory marketplace | Local dev build via `make install-dev` |

Both register the same MCP server name (`cred-mcp`) in `.mcp.json` — only the plugin wrapper differs.

## Troubleshooting

**MCP connection fails at Claude Code startup**

This is a race condition: Claude Code sometimes tries to reach the MCP server before it finishes initializing. It resolves on its own — wait a few seconds, then run `ping` to confirm:

```
AI: ping
→ {"ok": true, "version": "...", "time": "..."}
```

No binary reinstall or restart needed. If `ping` succeeds, the server is running fine.

## Related projects

- [pty-mcp](https://github.com/raychao-oao/pty-mcp) — sibling: interactive PTY sessions for AI agents (SSH, local shell, serial port).

## License

MIT — see [LICENSE](./LICENSE).
