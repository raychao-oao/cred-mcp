//go:build !darwin && !linux && !windows

package biometric

import "testing"

// On the catch-all stub platforms (BSDs etc.) Unlock is a no-op; verify
// it does not error. Linux, Windows, and darwin each have their own
// implementation files and tests.
func TestStubUnlockReturnsNil(t *testing.T) {
	if err := Unlock(); err != nil {
		t.Fatalf("stub Unlock should return nil, got %v", err)
	}
}
