//go:build darwin && !cgo

package biometric

// Unlock is a no-op stub used when CGO is disabled (e.g. cross-compilation).
// Touch ID requires cgo; without it biometric prompts are unavailable.
func Unlock() error {
	return ErrUnavailable
}

// Available reports whether biometric auth is available. Always false without cgo.
func Available() bool { return false }
