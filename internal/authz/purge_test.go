package authz

import (
	"testing"
	"time"
)

// Issue must sweep expired tokens so that unconsumed tokens do not
// accumulate for the lifetime of the process.
func TestIssue_PurgesExpiredTokens(t *testing.T) {
	s := NewStore()

	// Negative TTL produces an already-expired token.
	if _, err := s.Issue("item-a", "consumer-a", "ssh-login", -time.Second); err != nil {
		t.Fatalf("issue expired token: %v", err)
	}
	if _, err := s.Issue("item-b", "consumer-b", "ssh-login", time.Minute); err != nil {
		t.Fatalf("issue live token: %v", err)
	}

	s.mu.Lock()
	n := len(s.tokens)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("store holds %d tokens, want 1 (expired token should be purged on Issue)", n)
	}
}
