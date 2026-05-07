# cred-mcp

> Credential management MCP server for AI agents — store secrets in your OS keychain, hand them to AI workflows without ever putting plaintext into the LLM context.

**Status**: Pre-1.0 (`v0.0.x`). Expect breaking changes. Use locally for now.

## What it does

`cred-mcp` is a stdio MCP server. AI agents (Claude Code et al.) call its tools to **stash** and **retrieve** secrets. The plaintext value never appears in the conversation: `save_stash` reads it from your clipboard, `copy_stash` writes it back to your clipboard with a TTL.

```
You copy a password    →    You ask AI: "save it as asablue-ssh"
                            AI calls save_stash{name: "asablue-ssh"}
                            cred-mcp reads clipboard, writes OS keychain
                            (response carries only the name; LLM never sees the value)

Later, you ask AI: "I'm SSHing into asablue, get me the password"
                            AI calls copy_stash{name: "asablue-ssh"}
                            cred-mcp pulls from keychain, puts on clipboard for 30s
                            (response carries only metadata; LLM never sees the value)
You paste into the SSH prompt; clipboard auto-restores after the TTL.
```

## Tools (`v0.0.1`)

| Tool | Purpose |
|------|---------|
| `ping` | Health check. Returns server version + current time. |
| `save_stash` | Read user's clipboard, store under `name` in OS keychain. Clipboard is left untouched after — manage it as your normal workflow. |
| `copy_stash` | Read stored secret by `name`, put on clipboard for `ttl_seconds` (default 30, max 600). Auto-restores prior clipboard contents after the TTL unless the user has paste-and-replaced it. |
| `delete_stash` | Remove a stored secret by `name`. |

All tools that touch secrets return only metadata (`name`, `status`, `note`, `ttl_seconds`). The value is never serialized into the response or stderr logs.

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
```

Plaintext is read from stdin, never from argv (no shell history leak).

## Security model & known gaps

- **Plaintext never enters LLM context.** Tool responses and stderr logs carry only metadata (`name`, `status`, `note`, `ttl_seconds`). The clipboard is the side channel for the human user.
- **No biometric gating yet.** `go-keyring` does not set ACLs, so reads of cred-mcp keychain entries do **not** trigger Touch ID / Windows Hello. The effective security model right now is "unlocked once the user is logged into the OS". `feat/biometric` will plug this gap (cgo + LocalAuthentication on Mac, Hello API on Win) and become the unlock challenge for the session.
- **Session expiry: idle 30 min / absolute 8 hr.** The first secret-touching tool call after process start auto-unlocks the session. Activity refreshes the idle timer. Once either TTL fires, the session is locked permanently for that process — every subsequent `copy_stash` / `save_stash` / `delete_stash` returns an error telling the user to restart cred-mcp. `ping` always works (it is a health check). State does not persist across restarts. `feat/biometric` will replace "restart to recover" with an in-process Touch ID prompt.
- **No vault wiring yet.** `copy_stash` reads from the OS keychain directly. Bitwarden / Vaultwarden integration is `feat/vault` (planned).
- **Cross-device sync is out of scope.** Each device's keychain is independent — this is intentional, not a bug. Vaultwarden handles human-side sync; cred-mcp handles per-device AI-side access.

## Plugin packaging

Two parallel packages, mirroring the `pty-mcp` / `pty-mcp-dev` split:

| Package | Source | Purpose |
|---------|--------|---------|
| `cred-mcp` | GitHub release (planned) | End-user install via Claude Code marketplace |
| `cred-mcp-dev` | Local directory marketplace | Local dev build via `make install-dev` |

Both register the same MCP server name (`cred-mcp`) in `.mcp.json` — only the plugin wrapper differs.

## Related projects

- [pty-mcp](https://github.com/raychao-oao/pty-mcp) — sibling: interactive PTY sessions for AI agents (SSH, local shell, serial port).

## License

MIT — see [LICENSE](./LICENSE).
