package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/raychao-oao/cred-mcp/cmd/dev"
	"github.com/raychao-oao/cred-mcp/internal/mcp"
)

var version = "dev"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "dev" {
		runDev(os.Args[2:])
		return
	}

	fs := flag.NewFlagSet("cred-mcp", flag.ExitOnError)
	showVer := fs.Bool("version", false, "Show version")

	fs.Usage = func() {
		fmt.Println("cred-mcp - Credential management MCP server for AI agents")
		fmt.Printf("Version: %s\n\n", version)
		fmt.Println("Usage:")
		fmt.Println("  cred-mcp [options]                Run MCP server (stdio)")
		fmt.Println("  cred-mcp dev keychain <subcmd>    Manual keychain inspection (dev only)")
		fmt.Println("  cred-mcp dev clipboard <subcmd>   Manual clipboard testing (dev only)")
		fmt.Println()
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *showVer {
		fmt.Printf("cred-mcp %s\n", version)
		return
	}

	mcp.Serve(version)
}

func runDev(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cred-mcp dev <subcmd> [args...]")
		fmt.Fprintln(os.Stderr, "Subcommands: keychain, clipboard")
		os.Exit(2)
	}
	switch args[0] {
	case "keychain":
		dev.Keychain(args[1:])
	case "clipboard":
		dev.Clipboard(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown dev subcommand: %s\n", args[0])
		os.Exit(2)
	}
}
