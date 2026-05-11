package biometric

import (
	"errors"
	"testing"
)

// UserConsentVerificationResult enum values (from Windows.Security.Credentials.UI).
// PowerShell scripts in winhello.go exit with these codes.
//
//	0 Verified
//	1 DeviceNotPresent
//	2 NotConfiguredForUser
//	3 DisabledByPolicy
//	4 DeviceBusy
//	5 RetriesExhausted
//	6 Canceled
//
// mapWinHelloExitCode translates these to the biometric package's
// platform-agnostic error contract.
func TestMapWinHelloExitCode(t *testing.T) {
	cases := []struct {
		name string
		code int
		want error
	}{
		{"verified", 0, nil},
		{"device_not_present", 1, ErrUnavailable},
		{"not_configured", 2, ErrUnavailable},
		{"disabled_by_policy", 3, ErrUnavailable},
		{"canceled", 6, ErrCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapWinHelloExitCode(tc.code)
			if !errors.Is(got, tc.want) {
				t.Fatalf("code=%d: got %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}

// Transient / unknown codes should produce a non-nil error that is NEITHER
// of the sentinel errors. This lets callers distinguish a retryable / unknown
// failure from a deliberate cancel or a permanent unavailability.
func TestMapWinHelloExitCode_TransientAndUnknown(t *testing.T) {
	for _, code := range []int{4, 5, 999, -1} {
		t.Run("", func(t *testing.T) {
			got := mapWinHelloExitCode(code)
			if got == nil {
				t.Fatalf("code=%d: expected non-nil error", code)
			}
			if errors.Is(got, ErrCancelled) || errors.Is(got, ErrUnavailable) {
				t.Fatalf("code=%d: should not be a sentinel error, got %v", code, got)
			}
		})
	}
}
