# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-05-21

### Added
- **AI-native PAM protocol** — HPKE-based sealed credential delivery: AI acts as untrusted transport; plaintext never enters LLM context.
  - `internal/seal`: HPKE seal package (`DHKEM-X25519` + `HKDF-SHA256` + `ChaCha20Poly1305`) via Go stdlib `crypto/hpke`
  - `internal/registry`: consumer registry YAML loader + ACL check (glob-pattern item/purpose matching, `auto` / `required` approval modes)
  - `internal/authz`: single-use auth token store with TTL and `(item, consumer, purpose)` binding validation
  - `request_authorization` MCP tool — checks registry ACL, triggers biometric if `approval_mode: required`, issues a single-use auth token
  - `vault_seal` MCP tool — verifies ConsumerBundle identity key against registry, consumes auth token, fetches plaintext from vault, seals with HPKE, returns SealedBox; `box_id` generated server-side to prevent replay
  - `internal/e2e`: full in-process E2E smoke test covering bundle generation, ACL check, token lifecycle, HPKE seal, JSON round-trip, Open, and single-use enforcement

## [0.3.3] - 2026-05-20

### Added
- Plugin skill (`plugin/skills/cred-mcp/`) teaching Claude when and how to use cred-mcp tools securely — vault search/copy, stash operations, pty-mcp integration patterns, and security constraints.

## [0.3.2] - 2026-05-19

### Fixed
- Vault session expiry (HTTP 401) no longer requires `/mcp reconnect`: all vault operations now automatically re-authenticate and retry once when the Vaultwarden API session expires after idle 30 min or absolute 8 hr.
- Removed duplicate `vault_copy` entry in the tools list.

## [0.3.1] - 2026-05-19

### Fixed
- Plugin update no longer leaves the MCP server broken: `.mcp.json` now points to `scripts/run.sh`, a wrapper that auto-downloads the binary via `install.sh` if it is missing. `plugin update` skips `install.sh`, so without this wrapper every update broke the server on next launch.

## [0.3.0] - 2026-05-19

### Added
- `CRED_MCP_VAULT_*` environment variables as the primary configuration source, with `VAULTWARDEN_*` as a legacy fallback and OS keychain stash as the lowest-priority fallback.
- `vault_copy` now has a proper `inputSchema` with `id` and `ttl_seconds` fields (was missing in the tool definition).
- `vault_add` response now includes the `password_source` field so callers can confirm which source was used.

### Changed
- Tool descriptions rewritten from scratch for AI usability: each tool now states when to call it, what trigger phrases apply, and what to do next.
- `vault_search` now matches against the `username` field in addition to item name and URIs.
- `password_source` validation: unknown values are now rejected with a clear error message instead of silently falling through.
- `password_source` normalization: an empty value now defaults to `"dialog"` rather than causing undefined behavior.

### Fixed
- `gofmt` formatting on `internal/vault/item.go` (username search line was too long).
- `gofmt` formatting on `internal/mcp/server.go` (map literal indentation).

## [0.2.0] - 2026-05-14

### Added
- Vault integration via Vaultwarden API: `vault_search`, `vault_add`, `vault_update`, `vault_copy`.
- OS keychain stash layer: `save_stash`, `copy_stash`, `list_stash`, `delete_stash`.
- Session management with idle-30min / absolute-8hr TTL.
- Cross-platform OS keychain abstraction (`go-keyring`).
- Claude Code plugin packaging with install script and SHA256 checksum verification.

## [0.1.3] - 2026-04-28

### Fixed
- Initial public release with `ping` and basic stash operations.
