package biometric

import (
	"os"
	"strings"
)

// procVersionPath is overridable for tests. In production it points at the
// real kernel file on Linux; on non-Linux hosts it will simply not exist
// and isWSL will fall through to false.
var procVersionPath = "/proc/version"

// isWSL reports whether the current process is running inside WSL.
// Reads the real environment + /proc/version and delegates the decision
// to detectWSL.
func isWSL() bool {
	b, _ := os.ReadFile(procVersionPath)
	return detectWSL(os.Getenv("WSL_INTEROP"), b)
}

// detectWSL is the pure decision function — testable on any platform.
// WSL_INTEROP is set by WSL itself for every interactive shell; presence
// of the variable is the most reliable signal. Fall back to scanning
// /proc/version for "microsoft" or "wsl" for edge cases where the
// variable might have been stripped (rare).
func detectWSL(interop string, procVersion []byte) bool {
	if interop != "" {
		return true
	}
	s := strings.ToLower(string(procVersion))
	return strings.Contains(s, "microsoft") || strings.Contains(s, "wsl")
}
