//go:build !darwin

package biometric

import "testing"

// On non-darwin builds Unlock is a no-op stub; verify it does not error.
// Once a real implementation lands for that platform, this test should be
// replaced (or grow into a proper integration suite gated by build tags).
func TestStubUnlockReturnsNil(t *testing.T) {
	if err := Unlock(); err != nil {
		t.Fatalf("stub Unlock should return nil, got %v", err)
	}
}
