//go:build windows

package biometric

// Unlock on Windows shells out to powershell.exe which drives the WinRT
// UserConsentVerifier API (Windows Hello). Same bridge as the WSL2
// branch in biometric_linux.go — see winhello.go for the script.
//
// A future iteration may swap this for a native WinRT path via cgo + COM,
// but the PowerShell bridge keeps Windows builds CGO_ENABLED=0 which is a
// hard release-pipeline requirement (see reference_go_mcp_release_workflow
// in memory).
func Unlock() error {
	return windowsHelloUnlock()
}
