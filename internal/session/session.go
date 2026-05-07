// Package session manages the lifetime of cred-mcp's authorization to access
// stored secrets. A session has three states:
//
//	StateNew      — never used. The first Touch invokes the unlock policy
//	                and transitions to Active.
//	StateActive   — within both the idle TTL (default 30 min since last
//	                activity) and the absolute TTL (default 8 hr since
//	                unlock). Touch refreshes activity and stays Active.
//	StateExpired  — either TTL exceeded, or Lock() was called explicitly.
//	                Touch attempts the unlock policy again; on success the
//	                session returns to Active with fresh timers. With a
//	                real biometric policy this becomes a Touch ID / passcode
//	                re-prompt; with AutoUnlock it silently re-grants.
//
// Sessions live per-process. Each cred-mcp instance has its own state;
// nothing is persisted across restarts.
package session

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Defaults — change here if policy shifts; do not pepper magic numbers
// across handlers.
const (
	DefaultIdleTTL     = 30 * time.Minute
	DefaultAbsoluteTTL = 8 * time.Hour
)

// ErrExpired is returned by Touch when the session has been (or just
// became) Expired. Wrappers add detail about which TTL fired.
var ErrExpired = errors.New("session expired")

// State of a session.
type State int

const (
	StateNew State = iota
	StateActive
	StateExpired
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateActive:
		return "active"
	case StateExpired:
		return "expired"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// UnlockPolicy proves user identity at session unlock time (both StateNew →
// Active and StateExpired → Active). The signature is intentionally bare —
// a single yes/no — so backends never see the auth and so additional auth
// mechanisms (hardware token, WebAuthn) plug in without ceremony.
//
// Implementations live in internal/biometric (Touch ID / Windows Hello /
// future siblings). Tests wire injected policies via New.
type UnlockPolicy func() error

// AutoUnlock grants unlock without prompting. Used in tests and as a
// fallback on platforms without a real biometric implementation yet.
func AutoUnlock() error { return nil }

// Session holds per-process authorization state.
type Session struct {
	mu           sync.Mutex
	state        State
	unlockedAt   time.Time
	lastActivity time.Time
	idleTTL      time.Duration
	absoluteTTL  time.Duration
	now          func() time.Time
	unlock       UnlockPolicy
}

// New constructs a session with the given TTLs and unlock policy. A nil
// unlock policy is replaced with AutoUnlock.
func New(idleTTL, absoluteTTL time.Duration, unlock UnlockPolicy) *Session {
	if unlock == nil {
		unlock = AutoUnlock
	}
	return &Session{
		state:       StateNew,
		idleTTL:     idleTTL,
		absoluteTTL: absoluteTTL,
		now:         time.Now,
		unlock:      unlock,
	}
}

// Default is the process-wide session used by all MCP handlers.
var Default = New(DefaultIdleTTL, DefaultAbsoluteTTL, AutoUnlock)

// Touch authorizes a tool call. On nil error the caller may proceed.
// On non-nil error the call is denied; the caller surfaces the message
// to the user (e.g. "biometric authentication required, please retry").
//
// State transitions:
//
//	New      → unlock policy → Active     (or stay New on policy failure)
//	Active   → TTL within budget          → Active (refresh idle timer)
//	Active   → TTL exceeded               → Expired, then immediately
//	                                        attempt unlock as if from
//	                                        Expired (single Touch can
//	                                        recover transparently when
//	                                        the user authenticates)
//	Expired  → unlock policy → Active     (or stay Expired on failure)
func (s *Session) Touch() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	if s.state == StateActive {
		if since := now.Sub(s.unlockedAt); since > s.absoluteTTL {
			s.state = StateExpired
		} else if since := now.Sub(s.lastActivity); since > s.idleTTL {
			s.state = StateExpired
		} else {
			s.lastActivity = now
			return nil
		}
	}

	switch s.state {
	case StateNew, StateExpired:
		wasExpired := s.state == StateExpired
		if err := s.unlock(); err != nil {
			if wasExpired {
				// Surface ErrExpired so callers can distinguish "session was
				// expired and the user declined to re-authenticate" from
				// "first call could not unlock". Same wire format error,
				// different chain.
				return fmt.Errorf("%w; re-unlock denied: %w", ErrExpired, err)
			}
			return fmt.Errorf("session unlock failed: %w", err)
		}
		s.state = StateActive
		s.unlockedAt = now
		s.lastActivity = now
		return nil
	}

	return fmt.Errorf("session: unreachable state %v", s.state)
}

// Snapshot returns the current state and timestamps for diagnostics.
// Returned values are safe to read; the lock is released before return.
func (s *Session) Snapshot() (state State, unlockedAt, lastActivity time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.unlockedAt, s.lastActivity
}

// Lock forces the session into Expired state. Idempotent.
func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StateExpired
}

// SetNowForTesting overrides the clock seam and returns a restore func.
// Tests only.
func (s *Session) SetNowForTesting(nowFn func() time.Time) (restore func()) {
	s.mu.Lock()
	prev := s.now
	s.now = nowFn
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.now = prev
	}
}

// ResetForTesting returns the session to StateNew with cleared timestamps.
// Tests only.
func (s *Session) ResetForTesting() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StateNew
	s.unlockedAt = time.Time{}
	s.lastActivity = time.Time{}
}
