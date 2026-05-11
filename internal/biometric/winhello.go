package biometric

import (
	"errors"
	"fmt"
	"os/exec"
)

// helloScript drives Windows Hello via the WinRT UserConsentVerifier API.
// It polls the IAsyncOperation, then exits with the int value of the
// UserConsentVerificationResult enum (0..6). Status 2 (Canceled) or 3
// (Error) on the IAsyncOperation itself surfaces as exit 99, mapped to
// a generic transient error by mapWinHelloExitCode.
const helloScript = `$ErrorActionPreference = "Stop"
$null = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("cred-mcp wants to access your stashed secrets")
while ($op.Status -eq 0) { Start-Sleep -Milliseconds 50 }
if ($op.Status -eq 1) { exit [int]$op.GetResults() }
exit 99`

// windowsHelloUnlock runs the PowerShell bridge script and maps its exit
// code to the biometric error contract. Reachable on linux (WSL2 branch)
// and windows; on darwin and BSDs it compiles but is never called.
func windowsHelloUnlock() error {
	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", helloScript)
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return mapWinHelloExitCode(exitErr.ExitCode())
	}
	// exec.Command itself failed — powershell.exe not on PATH (likely
	// WSL with Win32 interop disabled, or a stripped-down Windows).
	return fmt.Errorf("biometric: powershell.exe not available: %w", err)
}

// mapWinHelloExitCode translates a UserConsentVerificationResult code
// (returned by the PowerShell bridge script) into the package's standard
// error contract. See TestMapWinHelloExitCode for the canonical table.
func mapWinHelloExitCode(code int) error {
	switch code {
	case 0:
		return nil
	case 1, 2, 3:
		// DeviceNotPresent / NotConfiguredForUser / DisabledByPolicy
		// all mean "no challenge possible on this machine, right now".
		return ErrUnavailable
	case 6:
		return ErrCancelled
	default:
		// 4 (DeviceBusy), 5 (RetriesExhausted), or anything unexpected.
		// Keep the code in the message so logs can diagnose transient cases.
		return fmt.Errorf("biometric: windows hello failed (code=%d)", code)
	}
}
