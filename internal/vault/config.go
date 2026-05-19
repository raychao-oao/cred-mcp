package vault

import (
	"fmt"
	"os"

	"github.com/raychao-oao/cred-mcp/internal/keychain"
)

// Config holds the Vaultwarden connection parameters.
type Config struct {
	BaseURL        string
	Email          string
	CFClientID     string
	CFClientSecret string
	MasterStashKey string // keychain key for the master password
}

// DefaultConfig loads config from env vars with keychain fallback.
//
// Primary env vars (preferred):
//   - CRED_MCP_VAULT_URL
//   - CRED_MCP_VAULT_EMAIL
//   - CRED_MCP_VAULT_CF_CLIENT_ID
//   - CRED_MCP_VAULT_CF_CLIENT_SECRET
//   - CRED_MCP_VAULT_MASTER_STASH_KEY  (optional, default: "vaultwarden-master")
//
// Legacy fallbacks (still accepted, lower priority):
//   - VAULTWARDEN_URL, VAULTWARDEN_EMAIL, VAULTWARDEN_CF_CLIENT_ID,
//     VAULTWARDEN_CF_CLIENT_SECRET, VAULTWARDEN_MASTER_STASH_KEY
//
// Keychain stash fallbacks (lowest priority):
//   - vaultwarden-url, vaultwarden-email, vaultwarden-cf-client-id,
//     vaultwarden-cf-client-secret
func DefaultConfig() (Config, error) {
	masterKey := firstEnv("CRED_MCP_VAULT_MASTER_STASH_KEY", "VAULTWARDEN_MASTER_STASH_KEY")
	if masterKey == "" {
		masterKey = "vaultwarden-master"
	}
	cfg := Config{
		BaseURL:        envOrStash("CRED_MCP_VAULT_URL", "VAULTWARDEN_URL", "vaultwarden-url"),
		Email:          envOrStash("CRED_MCP_VAULT_EMAIL", "VAULTWARDEN_EMAIL", "vaultwarden-email"),
		CFClientID:     envOrStash("CRED_MCP_VAULT_CF_CLIENT_ID", "VAULTWARDEN_CF_CLIENT_ID", "vaultwarden-cf-client-id"),
		CFClientSecret: envOrStash("CRED_MCP_VAULT_CF_CLIENT_SECRET", "VAULTWARDEN_CF_CLIENT_SECRET", "vaultwarden-cf-client-secret"),
		MasterStashKey: masterKey,
	}
	if cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("vault URL not configured (set CRED_MCP_VAULT_URL)")
	}
	if cfg.Email == "" {
		return Config{}, fmt.Errorf("vault email not configured (set CRED_MCP_VAULT_EMAIL)")
	}
	return cfg, nil
}

// firstEnv returns the value of the first non-empty env var in the list.
func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// envOrStash tries each env key in order, then falls back to a keychain stash lookup.
func envOrStash(primaryEnv, legacyEnv, stashKey string) string {
	if v := os.Getenv(primaryEnv); v != "" {
		return v
	}
	if v := os.Getenv(legacyEnv); v != "" {
		return v
	}
	v, _ := keychain.Get(stashKey)
	return v
}
