// Package biometric proves that the user is physically present at the device.
//
// It is the implementation behind session.UnlockPolicy. By design it knows
// nothing about secret storage — never import internal/keychain or any
// future backend package from here. Auth (this package) and Storage are
// orthogonal axes: a new backend must not require a new biometric path,
// and a new biometric path must not require a new backend.
package biometric

import "errors"

// ErrCancelled means the user dismissed the prompt without authenticating.
// The caller's session state should remain unchanged so a subsequent call
// can re-prompt.
var ErrCancelled = errors.New("biometric: user cancelled")

// ErrUnavailable means the platform cannot present a biometric / passcode
// challenge at all (e.g. on a system with no biometric hardware AND no
// device passcode set, or a platform without an implementation yet).
var ErrUnavailable = errors.New("biometric: authentication unavailable on this system")
