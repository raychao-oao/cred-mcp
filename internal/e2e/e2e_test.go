// Package e2e tests the full AI-native PAM protocol in-process without a real vault.
// It simulates the pty-mcp consumer side directly via consumersdk to avoid circular imports.
package e2e

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raychao-oao/cred-proto/pkg/consumersdk"
	"github.com/raychao-oao/cred-proto/pkg/credproto"
	"github.com/raychao-oao/cred-mcp/internal/authz"
	"github.com/raychao-oao/cred-mcp/internal/registry"
	"github.com/raychao-oao/cred-mcp/internal/seal"
)

// writeRegistry writes a minimal consumer registry YAML to a temp file and returns its path.
func writeRegistry(t *testing.T, consumerID string, identityPubKey []byte, items, purposes []string) string {
	t.Helper()
	content := fmt.Sprintf(`consumers:
  %s:
    identity_pub_key: %s
    allowed_items: [%s]
    allowed_purposes: [%s]
    approval_mode: auto
`, consumerID, hex.EncodeToString(identityPubKey), joinQuoted(items), joinQuoted(purposes))

	path := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	return path
}

func joinQuoted(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// TestFullProtocol exercises the complete two-step sealed-credential delivery:
//
//  1. Consumer (simulated pty-mcp) generates a signed ConsumerBundle.
//  2. Registry ACL check confirms access is allowed.
//  3. Auth token is issued (simulating request_authorization approval).
//  4. cred-mcp seals a fake secret against the bundle's session pubkey.
//  5. The SealedBox survives a JSON marshal/unmarshal round-trip.
//  6. Consumer opens the box and recovers the exact plaintext.
//  7. The auth token is confirmed single-use (second Consume returns error).
func TestFullProtocol(t *testing.T) {
	const (
		consumerID = "pty-mcp"
		itemID     = "item-ssh"
		purpose    = "ssh-login"
		boxID      = "box-e2e-1"
	)
	fakeSecret := []byte("s3cr3t-p4ssw0rd!")

	// ── Step 1: Simulate pty-mcp generating a ConsumerBundle ──────────────────
	ikPath := filepath.Join(t.TempDir(), "identity.key")
	ik, err := consumersdk.LoadOrGenerateIdentityKey(ikPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateIdentityKey: %v", err)
	}
	sk, err := consumersdk.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey: %v", err)
	}
	bundle, err := consumersdk.NewBundle(ik, sk, consumerID, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}

	// Bundle must be self-consistent before we do anything with it.
	if err := credproto.VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	// ── Step 2: Registry ACL check ────────────────────────────────────────────
	regPath := writeRegistry(t, consumerID, ik.PublicKeyBytes(), []string{itemID}, []string{purpose})
	reg, err := registry.Load(regPath)
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}
	mode, err := reg.CheckACL(consumerID, itemID, purpose)
	if err != nil {
		t.Fatalf("CheckACL: %v", err)
	}
	if mode != registry.ApprovalAuto {
		t.Fatalf("expected approval_mode=auto, got %q", mode)
	}

	// ── Step 3: Issue auth token (simulates biometric approval in auto mode) ──
	store := authz.NewStore()
	token, err := store.Issue(itemID, consumerID, purpose, 5*time.Minute)
	if err != nil {
		t.Fatalf("authz.Issue: %v", err)
	}

	// ── Step 4: Seal the secret ───────────────────────────────────────────────
	boxExp := time.Now().Add(5 * time.Minute).UTC()
	box, err := seal.Seal(bundle, itemID, purpose, boxID, boxExp, fakeSecret)
	if err != nil {
		t.Fatalf("seal.Seal: %v", err)
	}

	// ── Step 5: JSON wire round-trip ──────────────────────────────────────────
	wireBytes, err := json.Marshal(box)
	if err != nil {
		t.Fatalf("json.Marshal SealedBox: %v", err)
	}
	var box2 credproto.SealedBox
	if err := json.Unmarshal(wireBytes, &box2); err != nil {
		t.Fatalf("json.Unmarshal SealedBox: %v", err)
	}

	// ── Step 6: Consumer decrypts the sealed box ──────────────────────────────
	plaintext, err := consumersdk.Open(&box2, sk, bundle)
	if err != nil {
		t.Fatalf("consumersdk.Open: %v", err)
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	if string(plaintext) != string(fakeSecret) {
		t.Fatalf("decrypted %q, want %q", plaintext, fakeSecret)
	}

	// ── Step 7: Auth token is single-use ─────────────────────────────────────
	if err := store.Consume(token, itemID, consumerID, purpose); err != nil {
		t.Fatalf("first Consume should succeed: %v", err)
	}
	if err := store.Consume(token, itemID, consumerID, purpose); err == nil {
		t.Fatal("second Consume must return error (token already consumed)")
	}
}

// TestRegistryACL_Denied verifies that an unknown consumer or disallowed item/purpose is rejected.
func TestRegistryACL_Denied(t *testing.T) {
	ikPath := filepath.Join(t.TempDir(), "identity.key")
	ik, err := consumersdk.LoadOrGenerateIdentityKey(ikPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateIdentityKey: %v", err)
	}

	regPath := writeRegistry(t, "pty-mcp", ik.PublicKeyBytes(), []string{"item-ssh"}, []string{"ssh-login"})
	reg, err := registry.Load(regPath)
	if err != nil {
		t.Fatalf("registry.Load: %v", err)
	}

	tests := []struct {
		name       string
		consumerID string
		itemID     string
		purpose    string
		wantErr    error
	}{
		{"unknown consumer", "unknown-mcp", "item-ssh", "ssh-login", registry.ErrConsumerNotFound},
		{"disallowed item", "pty-mcp", "item-db", "ssh-login", registry.ErrItemDenied},
		{"disallowed purpose", "pty-mcp", "item-ssh", "sudo", registry.ErrPurposeDenied},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := reg.CheckACL(tc.consumerID, tc.itemID, tc.purpose)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestAuthzToken_Expired verifies that an expired token is rejected.
func TestAuthzToken_Expired(t *testing.T) {
	store := authz.NewStore()
	token, err := store.Issue("item-ssh", "pty-mcp", "ssh-login", -time.Second) // already expired
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Consume(token, "item-ssh", "pty-mcp", "ssh-login"); err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

// TestSeal_WrongSessionKey verifies that Open fails if a different session key is used.
func TestSeal_WrongSessionKey(t *testing.T) {
	ikPath := filepath.Join(t.TempDir(), "identity.key")
	ik, err := consumersdk.LoadOrGenerateIdentityKey(ikPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateIdentityKey: %v", err)
	}
	sk, err := consumersdk.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey: %v", err)
	}
	bundle, err := consumersdk.NewBundle(ik, sk, "pty-mcp", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}

	box, err := seal.Seal(bundle, "item-ssh", "ssh-login", "box-x", time.Now().Add(time.Minute), []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Generate a different session key — Open must reject the ciphertext.
	wrongSK, err := consumersdk.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey (wrong): %v", err)
	}
	if _, err := consumersdk.Open(box, wrongSK, bundle); err == nil {
		t.Fatal("Open with wrong session key must return error")
	}
}
