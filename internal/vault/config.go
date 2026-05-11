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
}

// DefaultConfig loads config from env vars with keychain fallback.
//
// Required env vars (or keychain stash keys):
//   - VAULTWARDEN_URL   / stash: vaultwarden-url
//   - VAULTWARDEN_EMAIL / stash: vaultwarden-email
//   - CF_ACCESS_CLIENT_ID     / stash: vaultwarden-cf-client-id
//   - CF_ACCESS_CLIENT_SECRET / stash: vaultwarden-cf-client-secret
func DefaultConfig() (Config, error) {
	cfg := Config{
		BaseURL:        envOrStash("VAULTWARDEN_URL", "vaultwarden-url"),
		Email:          envOrStash("VAULTWARDEN_EMAIL", "vaultwarden-email"),
		CFClientID:     envOrStash("VAULTWARDEN_CF_CLIENT_ID", "vaultwarden-cf-client-id"),
		CFClientSecret: envOrStash("VAULTWARDEN_CF_CLIENT_SECRET", "vaultwarden-cf-client-secret"),
	}
	if cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("Vaultwarden URL not configured (set VAULTWARDEN_URL or stash vaultwarden-url)")
	}
	if cfg.Email == "" {
		return Config{}, fmt.Errorf("Vaultwarden email not configured (set VAULTWARDEN_EMAIL or stash vaultwarden-email)")
	}
	return cfg, nil
}

func envOrStash(envKey, stashKey string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	v, _ := keychain.Get(stashKey)
	return v
}
