package vault

import (
	"testing"
)

func TestFirstEnv(t *testing.T) {
	t.Setenv("A", "alpha")
	t.Setenv("B", "beta")

	if got := firstEnv("A", "B"); got != "alpha" {
		t.Errorf("firstEnv: want %q, got %q", "alpha", got)
	}
	if got := firstEnv("MISSING", "B"); got != "beta" {
		t.Errorf("firstEnv fallback: want %q, got %q", "beta", got)
	}
	if got := firstEnv("MISSING1", "MISSING2"); got != "" {
		t.Errorf("firstEnv all-missing: want %q, got %q", "", got)
	}
}

func TestEnvOrStash_PrimaryTakesPrecedence(t *testing.T) {
	t.Setenv("CRED_MCP_VAULT_URL", "https://primary.example.com")
	t.Setenv("VAULTWARDEN_URL", "https://legacy.example.com")

	got := envOrStash("CRED_MCP_VAULT_URL", "VAULTWARDEN_URL", "vaultwarden-url")
	if got != "https://primary.example.com" {
		t.Errorf("primary env should win, got %q", got)
	}
}

func TestEnvOrStash_LegacyFallback(t *testing.T) {
	t.Setenv("VAULTWARDEN_URL", "https://legacy.example.com")

	got := envOrStash("CRED_MCP_VAULT_URL", "VAULTWARDEN_URL", "vaultwarden-url")
	if got != "https://legacy.example.com" {
		t.Errorf("legacy env fallback: want %q, got %q", "https://legacy.example.com", got)
	}
}

func TestDefaultConfig_PrimaryEnvVars(t *testing.T) {
	t.Setenv("CRED_MCP_VAULT_URL", "https://vault.example.com")
	t.Setenv("CRED_MCP_VAULT_EMAIL", "user@example.com")
	// Clear legacy vars so they don't interfere.
	t.Setenv("VAULTWARDEN_URL", "")
	t.Setenv("VAULTWARDEN_EMAIL", "")

	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseURL != "https://vault.example.com" {
		t.Errorf("BaseURL: want %q, got %q", "https://vault.example.com", cfg.BaseURL)
	}
	if cfg.Email != "user@example.com" {
		t.Errorf("Email: want %q, got %q", "user@example.com", cfg.Email)
	}
}

func TestDefaultConfig_LegacyEnvVars(t *testing.T) {
	// Primary vars absent, legacy present.
	t.Setenv("CRED_MCP_VAULT_URL", "")
	t.Setenv("CRED_MCP_VAULT_EMAIL", "")
	t.Setenv("VAULTWARDEN_URL", "https://legacy.example.com")
	t.Setenv("VAULTWARDEN_EMAIL", "legacy@example.com")

	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseURL != "https://legacy.example.com" {
		t.Errorf("BaseURL legacy fallback: want %q, got %q", "https://legacy.example.com", cfg.BaseURL)
	}
}

func TestDefaultConfig_MasterStashKey(t *testing.T) {
	t.Setenv("CRED_MCP_VAULT_URL", "https://vault.example.com")
	t.Setenv("CRED_MCP_VAULT_EMAIL", "user@example.com")
	t.Setenv("CRED_MCP_VAULT_MASTER_STASH_KEY", "my-master-key")
	t.Setenv("VAULTWARDEN_MASTER_STASH_KEY", "old-master-key")

	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MasterStashKey != "my-master-key" {
		t.Errorf("MasterStashKey: want %q, got %q", "my-master-key", cfg.MasterStashKey)
	}
}
