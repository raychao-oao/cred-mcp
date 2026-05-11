//go:build linux

package biometric

// Unlock on Linux currently has two branches:
//
//   - WSL2: bridge out to Windows Hello via powershell.exe. The user's
//     biometric hardware (fingerprint reader, Hello PIN, face cam) is
//     owned by Windows, not exposed to the Linux kernel inside WSL.
//   - Native Linux desktop: free pass (return nil) for now. Phase 2 will
//     replace this with a polkit CheckAuthorization D-Bus call. Until then
//     non-WSL Linux behaves like the pre-feat/biometric AutoUnlock policy.
//
// Headless Linux servers fall under "native Linux" today and also get the
// free pass; cred-mcp is not designed to run on operation targets so this
// is intentional rather than a gap.
func Unlock() error {
	if isWSL() {
		return windowsHelloUnlock()
	}
	// TODO(phase-2): replace with polkit CheckAuthorization once godbus
	// dependency and tw.nowhere.cred-mcp.policy file land.
	return nil
}
