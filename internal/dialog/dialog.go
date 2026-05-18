// Package dialog prompts the user for a secret via a platform-native GUI
// (osascript on macOS, Get-Credential on WSL2/Windows, zenity/kdialog on Linux)
// falling back to /dev/tty. The secret is never written to stdout or logs.
package dialog

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ReadSecret pops a native password dialog and returns the secret.
// Prompt is the message shown to the user.
func ReadSecret(prompt string) (string, error) {
	var b []byte
	var err error
	switch runtime.GOOS {
	case "darwin":
		b, err = readOsascript(prompt)
		if err == nil {
			return string(b), nil
		}
	case "linux":
		if isWSL2() {
			b, err = readPowerShell(prompt)
			if err == nil {
				return string(b), nil
			}
		}
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			if _, e := exec.LookPath("zenity"); e == nil {
				b, err = readZenity(prompt)
				if err == nil {
					return string(b), nil
				}
			}
			if _, e := exec.LookPath("kdialog"); e == nil {
				b, err = readKdialog(prompt)
				if err == nil {
					return string(b), nil
				}
			}
		}
	}
	b, err = readTTY(prompt)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func isWSL2() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

func readOsascript(prompt string) ([]byte, error) {
	// Prompt via env var to avoid AppleScript string injection.
	script := `tell application "System Events" to display dialog (system attribute "CRED_MCP_PROMPT") with hidden answer default answer "" buttons {"OK"} default button "OK"`
	cmd := exec.Command("osascript", "-e", script)
	cmd.Env = append(os.Environ(), "CRED_MCP_PROMPT="+prompt)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	result := strings.TrimSpace(string(out))
	const prefix = "button returned:OK, text returned:"
	if !strings.HasPrefix(result, prefix) {
		return nil, fmt.Errorf("osascript: unexpected output: %s", result)
	}
	return []byte(result[len(prefix):]), nil
}

func readPowerShell(prompt string) ([]byte, error) {
	escaped := strings.ReplaceAll(prompt, "'", "''")
	cmdStr := fmt.Sprintf(
		`$cred = Get-Credential -UserName "secret" -Message '%s'; $cred.GetNetworkCredential().Password`,
		escaped,
	)
	out, err := exec.Command("powershell.exe", "-NoProfile", "-Command", cmdStr).Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\r\n")), nil
}

func readZenity(prompt string) ([]byte, error) {
	out, err := exec.Command("zenity", "--password", "--title=cred-mcp", "--no-markup", "--text="+prompt).Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

func readKdialog(prompt string) ([]byte, error) {
	out, err := exec.Command("kdialog", "--password", prompt, "--title", "cred-mcp").Output()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(out), "\n")), nil
}

func readTTY(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open /dev/tty: %w", err)
	}
	defer tty.Close()

	if oldState, err := term.GetState(int(tty.Fd())); err == nil {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			if _, ok := <-sigCh; ok {
				term.Restore(int(tty.Fd()), oldState) //nolint:errcheck
			}
		}()
		defer func() {
			signal.Stop(sigCh)
			close(sigCh)
		}()
	}

	fmt.Fprintf(tty, "%s: ", prompt)
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("tty read: %w", err)
	}
	return secret, nil
}
