# Changelog

All notable changes to this project will be documented in this file.

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
