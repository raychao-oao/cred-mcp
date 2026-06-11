package mcp

import "testing"

// ping must surface the active auth mode so users can tell whether a real
// OS challenge (Touch ID / Windows Hello) protects the session or the
// server fell back to auto-unlock.
func TestPing_ReportsAuthMode(t *testing.T) {
	setupHandlerTest(t)

	prev := AuthMode
	AuthMode = "biometric"
	t.Cleanup(func() { AuthMode = prev })

	resp := callTool(t, "ping", map[string]any{})
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("ping failed: %s", text)
	}
	if got, _ := parsed["auth_mode"].(string); got != "biometric" {
		t.Fatalf("auth_mode = %q, want %q", got, "biometric")
	}
}

func TestPing_DefaultAuthModeIsAutoUnlock(t *testing.T) {
	setupHandlerTest(t)

	resp := callTool(t, "ping", map[string]any{})
	isErr, text, parsed := extract(t, resp)
	if isErr {
		t.Fatalf("ping failed: %s", text)
	}
	if got, _ := parsed["auth_mode"].(string); got != "auto_unlock" {
		t.Fatalf("auth_mode = %q, want %q (default)", got, "auto_unlock")
	}
}
