# cred-mcp

> Credential management MCP server for AI agents — store secrets in your OS keychain, hand them to AI workflows without ever putting plaintext into the LLM context.

**Status**: `v0.1.0` — early release. Core stash and vault tools are stable; biometric re-unlock (Touch ID / Windows Hello gating) is deferred to v0.2.0.

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
| `list_stash` | List metadata for all stored secrets (`name`, `source`, `created_at`). Values are never returned. Useful for migration: see what has already been moved into safe storage. |

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
