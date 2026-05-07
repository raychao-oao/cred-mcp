package clipboard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeBoard simulates the OS clipboard with locking so tests can manipulate it
// from multiple goroutines without racing on package-level swap-out variables.
type fakeBoard struct {
	mu    sync.Mutex
	value string
	err   error
}

func (b *fakeBoard) read() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.value, b.err
}

func (b *fakeBoard) write(s string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.value = s
	return nil
}

func (b *fakeBoard) set(v string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.value = v
}

// withFake replaces the package-level read/write seams for the duration of t.
func withFake(t *testing.T, initial string) *fakeBoard {
	t.Helper()
	b := &fakeBoard{value: initial}
	prevRead, prevWrite := readFunc, writeFunc
	readFunc = b.read
	writeFunc = b.write
	t.Cleanup(func() {
		readFunc = prevRead
		writeFunc = prevWrite
	})
	return b
}

func TestRestoresPreviousAfterTTL(t *testing.T) {
	b := withFake(t, "previous-content")

	wait, err := SetWithAutoClear(context.Background(), "secret-value", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("SetWithAutoClear: %v", err)
	}
	if v, _ := b.read(); v != "secret-value" {
		t.Fatalf("after Set, board=%q want %q", v, "secret-value")
	}

	if got := wait(); got != Restored {
		t.Fatalf("wait result = %v, want %v", got, Restored)
	}
	if v, _ := b.read(); v != "previous-content" {
		t.Fatalf("after TTL, board=%q want %q", v, "previous-content")
	}
}

func TestLeavesUserChangeUntouched(t *testing.T) {
	b := withFake(t, "previous-content")

	wait, err := SetWithAutoClear(context.Background(), "secret-value", 30*time.Millisecond)
	if err != nil {
		t.Fatalf("SetWithAutoClear: %v", err)
	}
	// User replaces the clipboard before TTL.
	b.set("user-pasted-this")

	if got := wait(); got != UserModified {
		t.Fatalf("wait result = %v, want %v", got, UserModified)
	}
	if v, _ := b.read(); v != "user-pasted-this" {
		t.Fatalf("after TTL, board=%q want %q (must not stomp user content)", v, "user-pasted-this")
	}
}

func TestContextCanceledKeepsSecret(t *testing.T) {
	b := withFake(t, "")

	ctx, cancel := context.WithCancel(context.Background())
	wait, err := SetWithAutoClear(ctx, "secret-value", time.Hour)
	if err != nil {
		t.Fatalf("SetWithAutoClear: %v", err)
	}
	cancel()

	if got := wait(); got != ContextCanceled {
		t.Fatalf("wait result = %v, want %v", got, ContextCanceled)
	}
	if v, _ := b.read(); v != "secret-value" {
		t.Fatalf("on cancel, board=%q want secret left in place", v)
	}
}

func TestRejectsNonPositiveTTL(t *testing.T) {
	withFake(t, "")
	if _, err := SetWithAutoClear(context.Background(), "x", 0); err == nil {
		t.Fatalf("ttl=0 should error")
	}
	if _, err := SetWithAutoClear(context.Background(), "x", -1); err == nil {
		t.Fatalf("negative ttl should error")
	}
}

func TestRead(t *testing.T) {
	b := withFake(t, "clipboard-content")
	got, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != "clipboard-content" {
		t.Fatalf("Read = %q, want %q", got, "clipboard-content")
	}
	_ = b
}

func TestPriorReadErrorIsTolerated(t *testing.T) {
	// Some Linux setups return errors on empty clipboard; SetWithAutoClear
	// must not abort the write because of that.
	b := &fakeBoard{value: "", err: errors.New("xclip: empty")}
	prevRead, prevWrite := readFunc, writeFunc
	readFunc = func() (string, error) {
		v, err := b.read()
		return v, err
	}
	writeFunc = b.write
	t.Cleanup(func() { readFunc, writeFunc = prevRead, prevWrite })

	if _, err := SetWithAutoClear(context.Background(), "secret", 10*time.Millisecond); err != nil {
		t.Fatalf("SetWithAutoClear should ignore prior-read error, got %v", err)
	}
}
