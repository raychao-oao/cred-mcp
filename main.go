package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/raychao-oao/cred-mcp/internal/mcp"
)

var version = "dev"

func main() {
	fs := flag.NewFlagSet("cred-mcp", flag.ExitOnError)
	showVer := fs.Bool("version", false, "Show version")

	fs.Usage = func() {
		fmt.Println("cred-mcp - Credential management MCP server for AI agents")
		fmt.Printf("Version: %s\n\n", version)
		fmt.Println("Usage:")
		fmt.Println("  cred-mcp [options]   Run MCP server (stdio)")
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
