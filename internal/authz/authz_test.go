package authz_test

import (
	"errors"
	"testing"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/authz"
)

func TestIssueAndConsume(t *testing.T) {
	s := authz.NewStore()
	tok, err := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	if err := s.Consume(tok, "item-42", "pty-mcp", "ssh-login"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
}

func TestConsume_SingleUse(t *testing.T) {
	s := authz.NewStore()
	tok, _ := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)
	s.Consume(tok, "item-42", "pty-mcp", "ssh-login")

	err := s.Consume(tok, "item-42", "pty-mcp", "ssh-login")
	if !errors.Is(err, authz.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound on second consume, got %v", err)
	}
}

func TestConsume_Expired(t *testing.T) {
	s := authz.NewStore()
	tok, _ := s.Issue("item-42", "pty-mcp", "ssh-login", -time.Second) // already expired

	err := s.Consume(tok, "item-42", "pty-mcp", "ssh-login")
	if !errors.Is(err, authz.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestConsume_NotFound(t *testing.T) {
	s := authz.NewStore()
	err := s.Consume("no-such-token", "item-42", "pty-mcp", "ssh-login")
	if !errors.Is(err, authz.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestConsume_WrongItem(t *testing.T) {
	s := authz.NewStore()
	tok, _ := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)

	err := s.Consume(tok, "item-WRONG", "pty-mcp", "ssh-login")
	if !errors.Is(err, authz.ErrTokenMismatch) {
		t.Fatalf("expected ErrTokenMismatch, got %v", err)
	}
}

func TestConsume_WrongConsumer(t *testing.T) {
	s := authz.NewStore()
	tok, _ := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)

	err := s.Consume(tok, "item-42", "wrong-mcp", "ssh-login")
	if !errors.Is(err, authz.ErrTokenMismatch) {
		t.Fatalf("expected ErrTokenMismatch, got %v", err)
	}
}

func TestConsume_WrongPurpose(t *testing.T) {
	s := authz.NewStore()
	tok, _ := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)

	err := s.Consume(tok, "item-42", "pty-mcp", "db-write")
	if !errors.Is(err, authz.ErrTokenMismatch) {
		t.Fatalf("expected ErrTokenMismatch, got %v", err)
	}
}

func TestIssue_TokensAreUnique(t *testing.T) {
	s := authz.NewStore()
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		tok, err := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token at iteration %d", i)
		}
		seen[tok] = true
	}
}

func TestPurgeExpired(t *testing.T) {
	s := authz.NewStore()
	// Issue an already-expired token
	s.Issue("item-42", "pty-mcp", "ssh-login", -time.Second)
	// Issue a valid token
	tok, _ := s.Issue("item-42", "pty-mcp", "ssh-login", time.Minute)

	s.PurgeExpired()

	// Valid token still consumable
	if err := s.Consume(tok, "item-42", "pty-mcp", "ssh-login"); err != nil {
		t.Fatalf("valid token purged: %v", err)
	}
}
