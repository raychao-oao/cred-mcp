# cred-mcp

> Credential management MCP server for AI agents — bridges Vaultwarden / Bitwarden with Claude Code, with secrets that never leak into LLM context.

**Status**: 🚧 Early development. API will change.

## What it does

`cred-mcp` lets AI agents (Claude Code et al.) safely use credentials stored in a Bitwarden-compatible vault (Vaultwarden recommended for self-hosting).

Three interaction modes:

1. **AI asks user** — when AI needs a credential not in vault, it prompts the user; if provided, AI offers to save.
2. **User asks AI** — user retrieves credentials through conversation (password to clipboard, username/metadata in context).
3. **AI auto-uses** *(planned)* — AI uses credentials directly without leaking plaintext into context (requires PTY/runner integration).

## Design principles

- **Plaintext never enters LLM context.** Passwords go to clipboard or via opaque references; only metadata (username, item names) appears in conversation.
- **Device-bound sessions.** Master password lives in OS keychain (macOS Keychain / Windows Credential Manager / Linux Secret Service). Biometric unlock where available (Touch ID, Windows Hello).
- **Web vault stays separate.** Human-side credential management uses Vaultwarden's native web vault. `cred-mcp` only handles the AI path.
- **Sliding TTL session.** AI session unlocks once via biometric, expires on 30-min idle or 8-hr absolute.

## Status

- [ ] MCP server skeleton (Go)
- [ ] Bitwarden CLI integration
- [ ] OS keychain abstraction (`go-keyring`)
- [ ] Clipboard mode with auto-clear
- [ ] Read tools (`lookup_credential`, `copy_password`, `copy_totp`, `list_credentials`)
- [ ] Write tools (`save_credential`, `update_password`, `generate_password`)
- [ ] First-run setup wizard
- [ ] Plugin packaging for Claude Code

## Related

- [pty-mcp](https://github.com/raychao-oao/pty-mcp) — sibling project, interactive PTY sessions for AI agents.

## License

MIT — see [LICENSE](./LICENSE).
