// Package keychain wraps the OS keychain (Keychain on macOS, Credential Manager
// on Windows, Secret Service on Linux desktops) with a small, opinionated API.
//
// All entries are namespaced under a single Service name so cred-mcp does not
// collide with other tools using the same keychain. The user's master password
// (and any future device-bound secrets) live here.
//
// Keys must not contain colons; we reserve them for future hierarchical use.
package keychain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

// Service is the keychain service name shared by all cred-mcp entries.
const Service = "cred-mcp"

// ErrNotFound is returned when a key is not present in the keychain.
var ErrNotFound = errors.New("keychain: entry not found")

// Set stores value under key. Overwrites any existing entry.
func Set(key, value string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := keyring.Set(Service, key, value); err != nil {
		return fmt.Errorf("keychain: set %q: %w", key, err)
	}
	return nil
}

// Get retrieves the value stored under key. Returns ErrNotFound if missing.
//
// On macOS the first call from a new binary may surface a Touch ID / password
// prompt; callers should be ready to block on user interaction.
func Get(key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	v, err := keyring.Get(Service, key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keychain: get %q: %w", key, err)
	}
	return v, nil
}

// Delete removes the entry under key. Returns ErrNotFound if it does not exist.
func Delete(key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := keyring.Delete(Service, key); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("keychain: delete %q: %w", key, err)
	}
	return nil
}

func validateKey(key string) error {
	if key == "" {
		return errors.New("keychain: key must not be empty")
	}
	if strings.ContainsRune(key, ':') {
		return errors.New("keychain: key must not contain ':'")
	}
	return nil
}
