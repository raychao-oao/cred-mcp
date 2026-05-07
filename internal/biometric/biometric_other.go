//go:build !darwin

package biometric

// Unlock on non-darwin currently grants access without a real challenge.
// This keeps Linux / Windows builds compiling and behaviorally compatible
// with the pre-feat/biometric AutoUnlock policy. A future change will
// replace this with a real platform implementation:
//
//   - Windows: LogonUserExEx / Hello via Credential Manager APIs
//   - Linux:   PAM / polkit, or punt to Vaultwarden's master password
//
// Until that lands, treat non-darwin builds as "unauthenticated by design"
// and document the gap in the README.
func Unlock() error {
	return nil
}
