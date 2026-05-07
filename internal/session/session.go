// Package session manages the lifetime of cred-mcp's authorization to access
// stored secrets. A session has three states:
//
//	StateNew      — never used. The first Touch invokes the unlock policy
//	                and transitions to Active.
//	StateActive   — within both the idle TTL (default 30 min since last
//	                activity) and the absolute TTL (default 8 hr since
//	                unlock). Touch refreshes activity and stays Active.
//	StateExpired  — either TTL exceeded, or Lock() was called explicitly.
//	                Refuses all Touch calls. Recovery in v1 requires
//	                restarting the cred-mcp process. feat/biometric will
//	                later replace the unlock policy with a Touch ID /
//	                Windows Hello challenge so re-unlock becomes possible
//	                in-process.
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

// UnlockPolicy decides whether unlock is granted on the StateNew → Active
// transition. v1 ships with AutoUnlock (no challenge). feat/biometric
// will swap in a policy that prompts Touch ID / Windows Hello.
type UnlockPolicy func() error

// AutoUnlock grants unlock without prompting. Used as the v1 default.
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
// On non-nil error the session is (or just became) Expired and the
// caller must surface that to the user — process restart is required
// to recover.
func (s *Session) Touch() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	switch s.state {
	case StateExpired:
		return fmt.Errorf("%w: requires cred-mcp restart", ErrExpired)

	case StateNew:
		if err := s.unlock(); err != nil {
			return fmt.Errorf("session unlock failed: %w", err)
		}
		s.state = StateActive
		s.unlockedAt = now
		s.lastActivity = now
		return nil

	case StateActive:
		if since := now.Sub(s.unlockedAt); since > s.absoluteTTL {
			s.state = StateExpired
			return fmt.Errorf("%w: absolute TTL exceeded (%s); requires cred-mcp restart", ErrExpired, since.Round(time.Second))
		}
		if since := now.Sub(s.lastActivity); since > s.idleTTL {
			s.state = StateExpired
			return fmt.Errorf("%w: idle TTL exceeded (%s); requires cred-mcp restart", ErrExpired, since.Round(time.Second))
		}
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
