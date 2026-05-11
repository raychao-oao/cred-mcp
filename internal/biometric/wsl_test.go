package biometric

import "testing"

// detectWSL is the pure decision function: given the WSL_INTEROP env var
// value and the contents of /proc/version, return whether the current
// process is running inside WSL.
//
// Both inputs are passed in (rather than read internally) so the function
// is testable on every host.
func TestDetectWSL(t *testing.T) {
	cases := []struct {
		name        string
		interop     string
		procVersion string
		want        bool
	}{
		{"interop env set wins", "/run/WSL/123_interop", "", true},
		{"interop env set ignores proc", "/x", "Linux version 6.0 generic", true},
		{"proc mentions microsoft", "", "Linux version 5.15 microsoft-standard-WSL2", true},
		{"proc mentions WSL only", "", "Linux version 5.15-wsl-something", true},
		{"proc mixed case Microsoft", "", "Linux Microsoft Corp", true},
		{"plain linux", "", "Linux version 6.0 generic", false},
		{"empty everything", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectWSL(tc.interop, []byte(tc.procVersion))
			if got != tc.want {
				t.Fatalf("detectWSL(%q, %q) = %v, want %v",
					tc.interop, tc.procVersion, got, tc.want)
			}
		})
	}
}
