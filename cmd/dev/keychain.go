// Package dev contains developer-facing CLI subcommands. These are NOT exposed
// over MCP and are only meant for manual verification during development.
package dev

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/raychao-oao/cred-mcp/internal/keychain"
)

// Keychain dispatches `cred-mcp dev keychain <subcmd>`.
func Keychain(args []string) {
	if len(args) == 0 {
		keychainUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "set":
		runKeychainSet(args[1:])
	case "get":
		runKeychainGet(args[1:])
	case "del", "delete":
		runKeychainDelete(args[1:])
	case "-h", "--help", "help":
		keychainUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", args[0])
		keychainUsage()
		os.Exit(2)
	}
}

func keychainUsage() {
	fmt.Println("Usage:")
	fmt.Println("  cred-mcp dev keychain set <key>      Read value from stdin and store under <key>")
	fmt.Println("  cred-mcp dev keychain get <key>      Print stored value (may prompt for biometric)")
	fmt.Println("  cred-mcp dev keychain del <key>      Remove entry")
	fmt.Println()
	fmt.Println("All entries live under the cred-mcp keychain service.")
	fmt.Println("Plaintext is read from stdin, never from argv.")
}

func runKeychainSet(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "set: exactly one <key> required")
		os.Exit(2)
	}
	key := args[0]

	value, err := readSecretFromStdin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "set: %v\n", err)
		os.Exit(1)
	}
	if value == "" {
		fmt.Fprintln(os.Stderr, "set: empty value, aborting")
		os.Exit(1)
	}

	if err := keychain.Set(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "set: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok: stored %q\n", key)
}

func runKeychainGet(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "get: exactly one <key> required")
		os.Exit(2)
	}
	v, err := keychain.Get(args[0])
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "get: %q not found\n", args[0])
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "get: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(v)
}

func runKeychainDelete(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "del: exactly one <key> required")
		os.Exit(2)
	}
	if err := keychain.Delete(args[0]); err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "del: %q not found\n", args[0])
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "del: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok: deleted %q\n", args[0])
}

func readSecretFromStdin() (string, error) {
	st, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if (st.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprint(os.Stderr, "value (will be hidden by terminal? no, just type and press Enter): ")
	}
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
