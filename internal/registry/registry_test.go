package registry_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/raychao-oao/cred-mcp/internal/registry"
)

func writeRegistry(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "registry-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	return f.Name()
}

func genIdentityHex(t *testing.T) (pub ed25519.PublicKey, hexKey string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, hex.EncodeToString(pub)
}

func TestLoad_Valid(t *testing.T) {
	_, hexKey := genIdentityHex(t)
	yaml := `
consumers:
  pty-mcp:
    identity_pub_key: "` + hexKey + `"
    allowed_items:
      - "server-*"
    allowed_purposes:
      - "ssh-login"
    approval_mode: required
`
	path := writeRegistry(t, yaml)
	reg, err := registry.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg, err := reg.Lookup("pty-mcp")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if cfg.ApprovalMode != registry.ApprovalRequired {
		t.Fatalf("expected required, got %v", cfg.ApprovalMode)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := registry.Load("/nonexistent/registry.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCheckACL_Allowed(t *testing.T) {
	_, hexKey := genIdentityHex(t)
	yaml := `
consumers:
  pty-mcp:
    identity_pub_key: "` + hexKey + `"
    allowed_items:
      - "server-*"
    allowed_purposes:
      - "ssh-login"
    approval_mode: auto
`
	reg, _ := registry.Load(writeRegistry(t, yaml))

	mode, err := reg.CheckACL("pty-mcp", "server-asablue", "ssh-login")
	if err != nil {
		t.Fatalf("CheckACL: %v", err)
	}
	if mode != registry.ApprovalAuto {
		t.Fatalf("expected auto, got %v", mode)
	}
}

func TestCheckACL_UnknownConsumer(t *testing.T) {
	_, hexKey := genIdentityHex(t)
	yaml := `
consumers:
  pty-mcp:
    identity_pub_key: "` + hexKey + `"
    allowed_items: ["server-*"]
    allowed_purposes: ["ssh-login"]
    approval_mode: auto
`
	reg, _ := registry.Load(writeRegistry(t, yaml))

	_, err := reg.CheckACL("unknown-mcp", "server-x", "ssh-login")
	if !errors.Is(err, registry.ErrConsumerNotFound) {
		t.Fatalf("expected ErrConsumerNotFound, got %v", err)
	}
}

func TestCheckACL_ItemDenied(t *testing.T) {
	_, hexKey := genIdentityHex(t)
	yaml := `
consumers:
  pty-mcp:
    identity_pub_key: "` + hexKey + `"
    allowed_items: ["server-*"]
    allowed_purposes: ["ssh-login"]
    approval_mode: auto
`
	reg, _ := registry.Load(writeRegistry(t, yaml))

	_, err := reg.CheckACL("pty-mcp", "email-nemo", "ssh-login")
	if !errors.Is(err, registry.ErrItemDenied) {
		t.Fatalf("expected ErrItemDenied, got %v", err)
	}
}

func TestCheckACL_PurposeDenied(t *testing.T) {
	_, hexKey := genIdentityHex(t)
	yaml := `
consumers:
  pty-mcp:
    identity_pub_key: "` + hexKey + `"
    allowed_items: ["server-*"]
    allowed_purposes: ["ssh-login"]
    approval_mode: auto
`
	reg, _ := registry.Load(writeRegistry(t, yaml))

	_, err := reg.CheckACL("pty-mcp", "server-asablue", "db-write")
	if !errors.Is(err, registry.ErrPurposeDenied) {
		t.Fatalf("expected ErrPurposeDenied, got %v", err)
	}
}

func TestLookup_IdentityPubKeyDecoded(t *testing.T) {
	pub, hexKey := genIdentityHex(t)
	yaml := `
consumers:
  pty-mcp:
    identity_pub_key: "` + hexKey + `"
    allowed_items: ["*"]
    allowed_purposes: ["*"]
    approval_mode: auto
`
	reg, _ := registry.Load(writeRegistry(t, yaml))
	cfg, _ := reg.Lookup("pty-mcp")

	if string(cfg.IdentityPubKey) != string(pub) {
		t.Fatalf("identity pub key mismatch")
	}
}
