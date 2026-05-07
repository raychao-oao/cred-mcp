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

func TestIdleExpiryLocks(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, advance := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}

	advance(31 * time.Minute)
	err := s.Touch()
	if err == nil {
		t.Fatalf("Touch after 31m idle should fail; got nil")
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("error chain missing ErrExpired; got %v", err)
	}
	if state, _, _ := s.Snapshot(); state != StateExpired {
		t.Fatalf("state after idle expiry = %v, want StateExpired", state)
	}
}

func TestAbsoluteExpiryLocksEvenWithActivity(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, advance := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}

	// Touch every 25min for ~9 hours. Idle never expires; absolute does.
	for i := 0; i < 24; i++ {
		advance(25 * time.Minute)
		err := s.Touch()
		if err != nil {
			// Should fire when total elapsed > 8 hr.
			elapsed := time.Duration(i+1) * 25 * time.Minute
			if elapsed <= 8*time.Hour {
				t.Fatalf("unexpected expiry at elapsed=%s err=%v", elapsed, err)
			}
			if !errors.Is(err, ErrExpired) {
				t.Fatalf("error chain missing ErrExpired; got %v", err)
			}
			return
		}
	}
	t.Fatalf("absolute TTL never fired across 10 hours")
}

func TestExpiredRefusesAllTouches(t *testing.T) {
	s := New(30*time.Minute, 8*time.Hour, AutoUnlock)
	now, _ := fixedClock(time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC))
	defer s.SetNowForTesting(now)()

	if err := s.Touch(); err != nil {
		t.Fatalf("first Touch: %v", err)
	}
	s.Lock()

	for i := 0; i < 3; i++ {
		err := s.Touch()
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("Touch %d after Lock should be ErrExpired; got %v", i, err)
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
