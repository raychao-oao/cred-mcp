package authz

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrTokenNotFound = errors.New("authz: token not found")
	ErrTokenExpired  = errors.New("authz: token expired")
	ErrTokenMismatch = errors.New("authz: token binding mismatch (item, consumer, or purpose)")
)

type entry struct {
	itemID     string
	consumerID string
	purpose    string
	expiresAt  time.Time
}

// Store is a thread-safe, in-memory single-use auth token store.
// Tokens are cleared on process restart; there is no persistence.
type Store struct {
	mu     sync.Mutex
	tokens map[string]*entry
}

// NewStore returns an empty Store ready for use.
func NewStore() *Store {
	return &Store{tokens: make(map[string]*entry)}
}

// Issue creates a new single-use token bound to (itemID, consumerID, purpose)
// with the given TTL. A negative TTL produces an already-expired token.
func (s *Store) Issue(itemID, consumerID, purpose string, ttl time.Duration) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)

	s.mu.Lock()
	s.tokens[tok] = &entry{
		itemID:     itemID,
		consumerID: consumerID,
		purpose:    purpose,
		expiresAt:  time.Now().Add(ttl),
	}
	s.mu.Unlock()
	return tok, nil
}

// Consume validates and atomically removes the token. Returns an error if the
// token is not found, expired, or any binding field does not match exactly.
func (s *Store) Consume(token, itemID, consumerID, purpose string) error {
	s.mu.Lock()
	e, ok := s.tokens[token]
	if ok {
		delete(s.tokens, token) // single-use: remove regardless of outcome
	}
	s.mu.Unlock()

	if !ok {
		return ErrTokenNotFound
	}
	if time.Now().After(e.expiresAt) {
		return ErrTokenExpired
	}
	if e.itemID != itemID || e.consumerID != consumerID || e.purpose != purpose {
		return ErrTokenMismatch
	}
	return nil
}

// PurgeExpired removes all expired tokens from the store. Call periodically
// to prevent unbounded memory growth from unConsumed expired tokens.
func (s *Store) PurgeExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, e := range s.tokens {
		if now.After(e.expiresAt) {
			delete(s.tokens, tok)
		}
	}
}
