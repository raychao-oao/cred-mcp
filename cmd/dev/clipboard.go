package dev

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/raychao-oao/cred-mcp/internal/clipboard"
)

// Clipboard dispatches `cred-mcp dev clipboard <subcmd>`.
func Clipboard(args []string) {
	if len(args) == 0 {
		clipboardUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "set":
		runClipboardSet(args[1:])
	case "clear":
		runClipboardClear(args[1:])
	case "-h", "--help", "help":
		clipboardUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", args[0])
		clipboardUsage()
		os.Exit(2)
	}
}

func clipboardUsage() {
	fmt.Println("Usage:")
	fmt.Println("  cred-mcp dev clipboard set [-ttl 30s]   Read value from stdin, put on clipboard, restore after TTL")
	fmt.Println("  cred-mcp dev clipboard clear            Empty the clipboard")
	fmt.Println()
	fmt.Println("Plaintext is read from stdin, never from argv. Ctrl-C cancels the wait")
	fmt.Println("but leaves the secret on the clipboard for the user to use.")
}

func runClipboardSet(args []string) {
	fs := flag.NewFlagSet("clipboard set", flag.ExitOnError)
	ttl := fs.Duration("ttl", 30*time.Second, "Time before the clipboard is restored to its previous value")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *ttl <= 0 {
		fmt.Fprintln(os.Stderr, "set: -ttl must be positive")
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "set: unexpected positional arguments")
		os.Exit(2)
	}

	value, err := readClipboardSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "set: %v\n", err)
		os.Exit(1)
	}
	if value == "" {
		fmt.Fprintln(os.Stderr, "set: empty value, aborting")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	wait, err := clipboard.SetWithAutoClear(ctx, value, *ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "set: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "secret on clipboard, will restore after %s (Ctrl-C to leave it in place)...\n", ttl.String())

	switch result := wait(); result {
	case clipboard.Restored:
		fmt.Fprintln(os.Stderr, "ok: clipboard restored")
	case clipboard.UserModified:
		fmt.Fprintln(os.Stderr, "ok: user changed clipboard before TTL, leaving it alone")
	case clipboard.ContextCanceled:
		fmt.Fprintln(os.Stderr, "interrupted: secret left on clipboard")
		os.Exit(130)
	}
}

func runClipboardClear(args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "clear: takes no arguments")
		os.Exit(2)
	}
	if err := clipboard.Clear(); err != nil {
		fmt.Fprintf(os.Stderr, "clear: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "ok: clipboard cleared")
}

func readClipboardSecret() (string, error) {
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
