package dev

import (
	"errors"
	"fmt"
	"os"

	"github.com/raychao-oao/cred-mcp/internal/biometric"
)

// Biometric dispatches `cred-mcp dev biometric <subcmd>`.
func Biometric(args []string) {
	if len(args) == 0 {
		biometricUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "test":
		runBiometricTest()
	case "-h", "--help", "help":
		biometricUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", args[0])
		biometricUsage()
		os.Exit(2)
	}
}

func biometricUsage() {
	fmt.Println("Usage:")
	fmt.Println("  cred-mcp dev biometric test      Trigger a biometric prompt and report the outcome")
	fmt.Println()
	fmt.Println("Useful for verifying that the OS prompt fires (Touch ID / passcode on macOS)")
	fmt.Println("without waiting for the session's idle TTL to expire inside the MCP server.")
	fmt.Println("On non-darwin platforms this currently returns success without any prompt.")
}

func runBiometricTest() {
	fmt.Println("Triggering biometric.Unlock(); respond to the system prompt if it appears...")
	err := biometric.Unlock()
	switch {
	case err == nil:
		fmt.Println("ok: authenticated")
	case errors.Is(err, biometric.ErrCancelled):
		fmt.Println("cancelled: user dismissed the prompt")
		os.Exit(1)
	case errors.Is(err, biometric.ErrUnavailable):
		fmt.Println("unavailable: this system has no biometric and no device passcode set")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
