//go:build !darwin && !linux && !windows

package biometric

// Unlock on platforms without a real implementation (BSDs, plan9, etc.)
// grants access without a challenge. Linux, Windows, and darwin each
// have their own dedicated files; this is the catch-all that keeps those
// other targets compiling. cred-mcp is not actively supported on these
// platforms — this stub exists so users who build from source can still
// produce a working binary.
func Unlock() error {
	return nil
}

// Available reports whether a real auth challenge is available. Always false
// on unsupported platforms — Unlock() grants access without prompting.
func Available() bool { return false }
