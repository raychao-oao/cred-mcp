#!/bin/sh
set -e

REPO="raychao-oao/cred-mcp"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
  darwin|linux) ;;
  *) echo "Unsupported OS: $OS (use the .exe from GitHub Releases on Windows)"; exit 1 ;;
esac

# Get latest version
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')
if [ -z "$VERSION" ]; then
  echo "Failed to get latest version"
  exit 1
fi

echo "Installing cred-mcp $VERSION ($OS/$ARCH)..."

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

curl -fsSL "$BASE_URL/cred-mcp-$OS-$ARCH" -o /tmp/cred-mcp
chmod +x /tmp/cred-mcp

if [ -w "$INSTALL_DIR" ]; then
  mv /tmp/cred-mcp "$INSTALL_DIR/cred-mcp"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv /tmp/cred-mcp "$INSTALL_DIR/cred-mcp"
fi

echo ""
echo "Installed: $INSTALL_DIR/cred-mcp"
echo ""
echo "Add to Claude Code:"
echo "  claude mcp add cred-mcp -- $INSTALL_DIR/cred-mcp"
echo ""
echo "First-time setup (store Vaultwarden config in keychain):"
echo "  printf 'https://your-vault.example.com' | cred-mcp dev keychain set vaultwarden-url"
echo "  printf 'you@example.com'                | cred-mcp dev keychain set vaultwarden-email"
echo "  printf '<cf-client-id>'                 | cred-mcp dev keychain set vaultwarden-cf-client-id"
echo "  printf '<cf-client-secret>'             | cred-mcp dev keychain set vaultwarden-cf-client-secret"
echo "  printf '<master-password>'              | cred-mcp dev keychain set vaultwarden-master"
echo ""
echo "See https://github.com/raychao-oao/cred-mcp for full setup guide."
