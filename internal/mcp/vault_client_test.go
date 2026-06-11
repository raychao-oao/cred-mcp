package mcp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/vault"
)

// resetVaultClientState snapshots and clears the package-level vault client
// cache so each test starts from "no client, no error". Cleanup restores the
// previous values (including the connectVault seam and backoff).
func resetVaultClientState(t *testing.T) {
	t.Helper()
	prevVault := defaultVault
	prevErr := defaultVaultErr
	prevErrAt := defaultVaultErrAt
	prevConnect := connectVault
	prevBackoff := vaultRetryBackoff
	defaultVault, defaultVaultErr, defaultVaultErrAt = nil, nil, time.Time{}
	t.Cleanup(func() {
		defaultVault = prevVault
		defaultVaultErr = prevErr
		defaultVaultErrAt = prevErrAt
		connectVault = prevConnect
		vaultRetryBackoff = prevBackoff
	})
}

func TestVaultClient_TransientFailureIsRetried(t *testing.T) {
	resetVaultClientState(t)
	vaultRetryBackoff = 0 // retry immediately

	calls := 0
	connectVault = func() (*vault.Client, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient network failure")
		}
		return vault.New("https://vault.example", "", ""), nil
	}

	if _, err := vaultClient(); err == nil {
		t.Fatal("first call should fail")
	}
	c, err := vaultClient()
	if err != nil {
		t.Fatalf("second call should retry and succeed, got: %v", err)
	}
	if c == nil {
		t.Fatal("second call returned nil client")
	}
	if calls != 2 {
		t.Fatalf("connectVault calls = %d, want 2", calls)
	}
}

func TestVaultClient_BackoffSuppressesImmediateRetry(t *testing.T) {
	resetVaultClientState(t)
	vaultRetryBackoff = time.Hour

	calls := 0
	connectVault = func() (*vault.Client, error) {
		calls++
		return nil, errors.New("still failing")
	}

	_, err1 := vaultClient()
	_, err2 := vaultClient()
	if err1 == nil || err2 == nil {
		t.Fatal("both calls should fail")
	}
	if calls != 1 {
		t.Fatalf("connectVault calls = %d, want 1 (second call within backoff window)", calls)
	}
	if !strings.Contains(err2.Error(), "still failing") {
		t.Fatalf("backoff should return the cached error, got: %v", err2)
	}
}

func TestVaultClient_SuccessIsCached(t *testing.T) {
	resetVaultClientState(t)

	calls := 0
	connectVault = func() (*vault.Client, error) {
		calls++
		return vault.New("https://vault.example", "", ""), nil
	}

	c1, err := vaultClient()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	c2, err := vaultClient()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if c1 != c2 {
		t.Fatal("successful client should be cached and reused")
	}
	if calls != 1 {
		t.Fatalf("connectVault calls = %d, want 1", calls)
	}
}
