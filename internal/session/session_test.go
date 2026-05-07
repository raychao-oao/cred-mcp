package session

import (
	"errors"
	"testing"
	"time"
)

// fixedClock returns a closure over a mutable now that tests can advance.
func fixedClock(start time.Time) (now func() time.Time, advance func(time.Duration)) {
	t := start
	return func() time.Time { return t },
		func(d time.Duration) { t = t.Add(d) }
}

// togglePolicy returns an UnlockPolicy plus a setter that flips between
// accept and deny. Lets a single test exercise both transitions without
// constructing a new Session each time.
func togglePolicy() (policy UnlockPolicy, setDeny func(bool)) {
	deny := false
	return func() error {
			if deny {
				return errors.New("denied by policy")
			}
			return nil
		}, func(d bool) {
			deny = d
		}
}

func TestStateNewFirstTouchActivates(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, _ := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if state, _, _ := s.Snapshot(); state != StateNew {
		t.Fatalf("initial state = %v, want StateNew", state)
	}
	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch returned %v, want nil", err)
	}
	state, unlockedAt, lastActivity := s.Snapshot()
	if state != StateActive {
		t.Fatalf("state after first Touch = %v, want StateActive", state)
	}
	if unlockedAt.IsZero() || lastActivity.IsZero() {
		t.Fatalf("timestamps not set: unlockedAt=%v lastActivity=%v", unlockedAt, lastActivity)
	}
	if !unlockedAt.Equal(lastActivity) {
		t.Fatalf("first Touch should set unlockedAt == lastActivity; got %v vs %v", unlockedAt, lastActivity)
	}
}

func TestUnlockPolicyFailureKeepsNew(t *testing.T) {
	policyErr := errors.New("biometric prompt cancelled")
	s := New(30*time.Minute, 8*time.Hour, func() error { return policyErr })
	now, _ := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	err := s.Touch()
	if err == nil {
		t.Fatalf("Touch with failing policy returned nil; want error")
	}
	if !errors.Is(err, policyErr) {
		t.Fatalf("error chain missing policy err; got %v", err)
	}
	// The "first unlock" path must NOT wrap ErrExpired — that sentinel is
	// reserved for the "was expired, declined re-unlock" case.
	if errors.Is(err, ErrExpired) {
		t.Fatalf("StateNew unlock failure should not wrap ErrExpired; got %v", err)
	}
	if state, _, _ := s.Snapshot(); state != StateNew {
		t.Fatalf("state after failed unlock = %v, want StateNew so caller can retry", state)
	}
}

func TestActivityRefreshesIdleTimer(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, advance := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}

	// Five Touches separated by 25 min — never crosses 30 min idle.
	for i := 0; i < 5; i++ {
		advance(25 * time.Minute)
		if err := s.Touch(); err != nil {
			t.Fatalf("Touch %d at %s should succeed; got %v", i, now().Format(time.RFC3339), err)
		}
		if state, _, _ := s.Snapshot(); state != StateActive {
			t.Fatalf("state after refresh %d = %v, want StateActive", i, state)
		}
	}
}

// Idle expiry plus an accepting policy: the session re-unlocks transparently
// on the next Touch and timers reset. With biometric.Unlock as the policy
// this corresponds to a Touch ID re-prompt the user accepts.
func TestIdleExpiryWithAcceptingPolicyRecovers(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, advance := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}
	originalUnlock := mustUnlockedAt(t, s)

	advance(31 * time.Minute)
	if err := s.Touch(); err != nil {
		t.Fatalf("Touch after 31m idle with accepting policy should re-unlock; got %v", err)
	}

	state, unlockedAt, lastActivity := s.Snapshot()
	if state != StateActive {
		t.Fatalf("state after re-unlock = %v, want StateActive", state)
	}
	if !unlockedAt.After(originalUnlock) {
		t.Fatalf("unlockedAt should advance on re-unlock; original=%v current=%v", originalUnlock, unlockedAt)
	}
	if !unlockedAt.Equal(lastActivity) {
		t.Fatalf("re-unlock should set unlockedAt == lastActivity; got %v vs %v", unlockedAt, lastActivity)
	}
}

// Idle expiry plus a denying policy: Touch fails AND state becomes Expired.
// The error chain includes ErrExpired so callers can distinguish recovery
// failure from a fresh unlock failure.
func TestIdleExpiryWithDenyingPolicyKeepsExpired(t *testing.T) {
	policy, setDeny := togglePolicy()
	s := New(30*time.Minute, 8*time.Hour, policy)
	now, advance := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}

	advance(31 * time.Minute)
	setDeny(true)
	err := s.Touch()
	if err == nil {
		t.Fatalf("Touch after idle expiry + deny should fail; got nil")
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("denied recovery should wrap ErrExpired; got %v", err)
	}
	if state, _, _ := s.Snapshot(); state != StateExpired {
		t.Fatalf("state after denied recovery = %v, want StateExpired", state)
	}

	// Once the user authenticates the next Touch succeeds.
	setDeny(false)
	if err := s.Touch(); err != nil {
		t.Fatalf("Touch after policy accepts again: %v", err)
	}
	if state, _, _ := s.Snapshot(); state != StateActive {
		t.Fatalf("state after recovery = %v, want StateActive", state)
	}
}

func TestAbsoluteExpiryLocksEvenWithActivity(t *testing.T) {
	policy, setDeny := togglePolicy()
	s := New(30*time.Minute, 8*time.Hour, policy)
	now, advance := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}

	// Touch every 25min. Idle never exceeds; absolute should fire eventually.
	// Once it fires the policy denies, so we observe the Expired state.
	for i := 0; i < 24; i++ {
		advance(25 * time.Minute)
		elapsed := time.Duration(i+1) * 25 * time.Minute
		if elapsed > 8*time.Hour {
			setDeny(true)
		}
		err := s.Touch()
		if err == nil {
			if elapsed > 8*time.Hour {
				t.Fatalf("absolute TTL should have fired by elapsed=%s but Touch succeeded", elapsed)
			}
			continue
		}
		// Within 8 hours of unlock, no error expected.
		if elapsed <= 8*time.Hour {
			t.Fatalf("unexpected expiry at elapsed=%s err=%v", elapsed, err)
		}
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("absolute expiry + deny should wrap ErrExpired; got %v", err)
		}
		if state, _, _ := s.Snapshot(); state != StateExpired {
			t.Fatalf("state after absolute expiry = %v, want StateExpired", state)
		}
		return
	}
	t.Fatalf("absolute TTL never fired across 10 hours of touches")
}

func TestLockThenAcceptingPolicyRecovers(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, _ := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}
	s.Lock()
	if state, _, _ := s.Snapshot(); state != StateExpired {
		t.Fatalf("state after Lock = %v, want StateExpired", state)
	}

	if err := s.Touch(); err != nil {
		t.Fatalf("Touch after Lock with accepting policy should re-unlock; got %v", err)
	}
	if state, _, _ := s.Snapshot(); state != StateActive {
		t.Fatalf("state after re-unlock = %v, want StateActive", state)
	}
}

func TestLockThenDenyingPolicyKeepsExpired(t *testing.T) {
	policy, setDeny := togglePolicy()
	s := New(30*time.Minute, 8*time.Hour, policy)
	now, _ := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}
	s.Lock()
	setDeny(true)

	for i := 0; i < 3; i++ {
		err := s.Touch()
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("Touch %d after Lock with denying policy should wrap ErrExpired; got %v", i, err)
		}
		if state, _, _ := s.Snapshot(); state != StateExpired {
			t.Fatalf("state after denied Touch %d = %v, want StateExpired", i, state)
		}
	}
}

func TestLockIsIdempotent(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	s.Lock()
	s.Lock() // must not deadlock or panic
	if state, _, _ := s.Snapshot(); state != StateExpired {
		t.Fatalf("state after Lock = %v, want StateExpired", state)
	}
}

func TestResetForTestingReturnsToNew(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, _ := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	s.Lock()
	s.ResetForTesting()
	state, unlockedAt, lastActivity := s.Snapshot()
	if state != StateNew {
		t.Fatalf("state after Reset = %v, want StateNew", state)
	}
	if !unlockedAt.IsZero() || !lastActivity.IsZero() {
		t.Fatalf("Reset should clear timestamps; got %v / %v", unlockedAt, lastActivity)
	}
	// Reset should allow another full lifecycle.
	if err := s.Touch(); err != nil {
		t.Fatalf("Touch after Reset failed: %v", err)
	}
}

func TestStateString(t *testing.T) {
	cases := map[State]string{
		StateNew:     "new",
		StateActive:  "active",
		StateExpired: "expired",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func mustUnlockedAt(t *testing.T, s *Session) time.Time {
	t.Helper()
	_, ua, _ := s.Snapshot()
	if ua.IsZero() {
		t.Fatalf("expected unlockedAt to be set, was zero")
	}
	return ua
}
