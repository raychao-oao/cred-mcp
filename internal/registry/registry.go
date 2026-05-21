package registry

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ApprovalMode controls whether a human biometric approval is required.
type ApprovalMode string

const (
	ApprovalAuto     ApprovalMode = "auto"
	ApprovalRequired ApprovalMode = "required"
)

var (
	ErrConsumerNotFound = errors.New("registry: consumer not found")
	ErrItemDenied       = errors.New("registry: item not in consumer's allowed list")
	ErrPurposeDenied    = errors.New("registry: purpose not in consumer's allowed list")
)

// ConsumerConfig is the resolved configuration for a registered consumer MCP.
type ConsumerConfig struct {
	IdentityPubKey  []byte       // Ed25519 public key, 32 bytes
	AllowedItems    []string     // glob patterns (e.g. "server-*", "*")
	AllowedPurposes []string     // exact strings or "*"
	ApprovalMode    ApprovalMode
}

// Registry holds the loaded and parsed consumer registry.
type Registry struct {
	consumers map[string]*ConsumerConfig
}

// rawConsumer is the YAML wire shape for a consumer entry.
type rawConsumer struct {
	IdentityPubKey  string       `yaml:"identity_pub_key"`
	AllowedItems    []string     `yaml:"allowed_items"`
	AllowedPurposes []string     `yaml:"allowed_purposes"`
	ApprovalMode    ApprovalMode `yaml:"approval_mode"`
}

type rawFile struct {
	Consumers map[string]rawConsumer `yaml:"consumers"`
}

// Load parses a YAML registry file and returns a ready-to-use Registry.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}

	var raw rawFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}

	reg := &Registry{consumers: make(map[string]*ConsumerConfig, len(raw.Consumers))}
	for id, rc := range raw.Consumers {
		pubKey, err := hex.DecodeString(rc.IdentityPubKey)
		if err != nil {
			return nil, fmt.Errorf("registry: consumer %q has invalid identity_pub_key: %w", id, err)
		}
		mode := rc.ApprovalMode
		if mode == "" {
			mode = ApprovalRequired
		}
		reg.consumers[id] = &ConsumerConfig{
			IdentityPubKey:  pubKey,
			AllowedItems:    rc.AllowedItems,
			AllowedPurposes: rc.AllowedPurposes,
			ApprovalMode:    mode,
		}
	}
	return reg, nil
}

// Lookup returns the ConsumerConfig for the given consumer ID.
func (r *Registry) Lookup(consumerID string) (*ConsumerConfig, error) {
	cfg, ok := r.consumers[consumerID]
	if !ok {
		return nil, ErrConsumerNotFound
	}
	return cfg, nil
}

// CheckACL verifies that consumerID is allowed to access itemID for purpose.
// Returns the ApprovalMode that must be satisfied before sealing.
func (r *Registry) CheckACL(consumerID, itemID, purpose string) (ApprovalMode, error) {
	cfg, err := r.Lookup(consumerID)
	if err != nil {
		return "", err
	}
	if !matchAny(cfg.AllowedItems, itemID) {
		return "", ErrItemDenied
	}
	if !matchAny(cfg.AllowedPurposes, purpose) {
		return "", ErrPurposeDenied
	}
	return cfg.ApprovalMode, nil
}

// matchAny returns true if s matches any pattern in the list.
// Patterns support a single trailing "*" wildcard or literal "*" (match all).
func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if p == "*" || p == s {
			return true
		}
		// prefix wildcard: "server-*" matches "server-asablue"
		if len(p) > 0 && p[len(p)-1] == '*' && len(s) >= len(p)-1 && s[:len(p)-1] == p[:len(p)-1] {
			return true
		}
	}
	return false
}
