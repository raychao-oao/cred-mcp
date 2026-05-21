package mcp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/authz"
	"github.com/raychao-oao/cred-mcp/internal/biometric"
	"github.com/raychao-oao/cred-mcp/internal/registry"
	"github.com/raychao-oao/cred-mcp/internal/seal"
	"github.com/raychao-oao/cred-mcp/internal/vault"
	"github.com/raychao-oao/cred-proto/pkg/credproto"
)

const (
	defaultAuthzTTLSeconds = 300  // 5 minutes
	maxAuthzTTLSeconds     = 1800 // 30 minutes
	defaultBoxTTLSeconds   = 300  // 5 minutes
	maxBoxTTLSeconds       = 3600 // 1 hour
)

var defaultAuthzStore = authz.NewStore()

var (
	registryOnce sync.Once
	defaultReg   *registry.Registry
	defaultRegErr error
)

func loadRegistry() (*registry.Registry, error) {
	registryOnce.Do(func() {
		path := os.Getenv("CRED_MCP_REGISTRY")
		if path == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				defaultRegErr = fmt.Errorf("registry: cannot find home dir: %w", err)
				return
			}
			path = filepath.Join(home, ".config", "cred-mcp", "registry.yaml")
		}
		reg, err := registry.Load(path)
		if err != nil {
			defaultRegErr = fmt.Errorf("registry: %w", err)
			return
		}
		defaultReg = reg
		log.Printf("registry: loaded from %s", path)
	})
	return defaultReg, defaultRegErr
}

// --- request_authorization ---

type requestAuthzArgs struct {
	ItemID     string `json:"item_id"`
	ConsumerID string `json:"consumer_id"`
	Purpose    string `json:"purpose"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func handleRequestAuthorization(id any, raw json.RawMessage) response {
	var args requestAuthzArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
	}
	if args.ItemID == "" || args.ConsumerID == "" || args.Purpose == "" {
		return toolErrResp(id, "item_id, consumer_id, and purpose are required")
	}
	clamp(&args.TTLSeconds, defaultAuthzTTLSeconds, maxAuthzTTLSeconds)

	reg, err := loadRegistry()
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("registry unavailable: %v", err))
	}
	approvalMode, err := reg.CheckACL(args.ConsumerID, args.ItemID, args.Purpose)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("access denied: %v", err))
	}

	if approvalMode == registry.ApprovalRequired {
		if err := biometric.Unlock(); err != nil {
			return toolErrResp(id, fmt.Sprintf("biometric authentication failed: %v", err))
		}
	}

	tok, err := defaultAuthzStore.Issue(args.ItemID, args.ConsumerID, args.Purpose, time.Duration(args.TTLSeconds)*time.Second)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("failed to issue token: %v", err))
	}

	log.Printf("request_authorization: issued token consumer=%s item=%s purpose=%s mode=%s",
		args.ConsumerID, args.ItemID, args.Purpose, approvalMode)

	return okResp(id, map[string]any{
		"auth_token":    tok,
		"approval_mode": string(approvalMode),
		"ttl_seconds":   args.TTLSeconds,
		"consumer_id":   args.ConsumerID,
		"item_id":       args.ItemID,
		"purpose":       args.Purpose,
	})
}

// --- vault_seal ---

type vaultSealArgs struct {
	ItemID         string          `json:"item_id"`
	ConsumerBundle json.RawMessage `json:"consumer_bundle"`
	AuthToken      string          `json:"auth_token"`
	Purpose        string          `json:"purpose"`
	BoxTTLSeconds  int             `json:"box_ttl_seconds"`
}

func handleVaultSeal(id any, raw json.RawMessage) response {
	var args vaultSealArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return errResp(id, -32602, fmt.Sprintf("invalid arguments: %v", err))
	}
	if args.ItemID == "" || args.AuthToken == "" || args.Purpose == "" || len(args.ConsumerBundle) == 0 {
		return toolErrResp(id, "item_id, auth_token, purpose, and consumer_bundle are required")
	}
	clamp(&args.BoxTTLSeconds, defaultBoxTTLSeconds, maxBoxTTLSeconds)

	// Parse and verify bundle
	var bundle credproto.ConsumerBundle
	if err := json.Unmarshal(args.ConsumerBundle, &bundle); err != nil {
		return toolErrResp(id, fmt.Sprintf("invalid consumer_bundle: %v", err))
	}
	if err := credproto.VerifyBundle(&bundle); err != nil {
		return toolErrResp(id, fmt.Sprintf("bundle verification failed: %v", err))
	}

	// Registry: confirm consumer is registered and identity key matches
	reg, err := loadRegistry()
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("registry unavailable: %v", err))
	}
	cfg, err := reg.Lookup(bundle.ConsumerID)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("consumer not registered: %v", err))
	}
	if !bytes.Equal(cfg.IdentityPubKey, bundle.IdentityPubKey) {
		return toolErrResp(id, "consumer identity key does not match registry — possible impersonation")
	}

	// Consume auth token — single-use, validates (item, consumer, purpose) binding
	if err := defaultAuthzStore.Consume(args.AuthToken, args.ItemID, bundle.ConsumerID, args.Purpose); err != nil {
		return toolErrResp(id, fmt.Sprintf("auth token invalid: %v", err))
	}

	// Fetch plaintext from vault
	var plaintext string
	if err := withVault(func(c *vault.Client) error {
		var ferr error
		plaintext, ferr = c.Secret(args.ItemID)
		return ferr
	}); err != nil {
		return toolErrResp(id, fmt.Sprintf("vault error: %v", err))
	}

	// Generate box_id server-side (prevents AI from forcing replays via box_id reuse)
	boxID, err := randomHex(8)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("box_id generation failed: %v", err))
	}

	boxExp := time.Now().Add(time.Duration(args.BoxTTLSeconds) * time.Second).UTC()
	plaintextBytes := []byte(plaintext)
	box, err := seal.SealAndZeroize(&bundle, args.ItemID, args.Purpose, boxID, boxExp, plaintextBytes)
	if err != nil {
		return toolErrResp(id, fmt.Sprintf("seal failed: %v", err))
	}

	log.Printf("vault_seal: sealed item=%s consumer=%s purpose=%s box_id=%s",
		args.ItemID, bundle.ConsumerID, args.Purpose, boxID)

	boxJSON, _ := json.MarshalIndent(box, "", "  ")
	return okResp(id, map[string]any{
		"sealed_box": json.RawMessage(boxJSON),
		"box_id":     boxID,
		"expires_at": boxExp.Format(time.RFC3339),
	})
}

func clamp(v *int, defaultVal, max int) {
	if *v <= 0 {
		*v = defaultVal
	}
	if *v > max {
		*v = max
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
