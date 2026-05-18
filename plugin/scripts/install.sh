#!/bin/bash
# cred-mcp binary installer
# Downloads the correct binary from GitHub releases into ${CLAUDE_PLUGIN_ROOT}/bin/

set -e

if [ -z "${CLAUDE_PLUGIN_ROOT}" ]; then
    echo "[cred-mcp] ERROR: CLAUDE_PLUGIN_ROOT is not set" >&2
    exit 1
fi

VERSION="v0.2.0"
REPO="raychao-oao/cred-mcp"
BIN_DIR="${CLAUDE_PLUGIN_ROOT}/bin"
BIN_PATH="${BIN_DIR}/cred-mcp"
TMP_BIN="${BIN_PATH}.tmp"
SUMS_TMP=$(mktemp)

trap 'rm -f "${TMP_BIN}" "${SUMS_TMP}"' EXIT

# Skip if already installed at correct version
if [ -f "${BIN_PATH}" ] && [ -x "${BIN_PATH}" ]; then
    INSTALLED=$("${BIN_PATH}" -version 2>/dev/null | awk '{print $NF}' || echo "unknown")
    if [ "${INSTALLED}" = "${VERSION}" ]; then
        exit 0
    fi
    echo "[cred-mcp] Upgrading from ${INSTALLED} to ${VERSION}..."
fi

mkdir -p "${BIN_DIR}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "${OS}" in
    darwin|linux) ;;
    *) echo "[cred-mcp] Unsupported OS: ${OS}" >&2; exit 1 ;;
esac

ARCH=$(uname -m)
case "${ARCH}" in
    x86_64)        ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "[cred-mcp] Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
esac

BINARY="cred-mcp-${OS}-${ARCH}"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
URL="${BASE_URL}/${BINARY}"

echo "[cred-mcp] Downloading ${BINARY} ${VERSION}..."
if ! curl -fsSL --connect-timeout 10 --max-time 25 --retry 2 "${URL}" -o "${TMP_BIN}"; then
    echo "[cred-mcp] ERROR: Download failed: ${URL}" >&2
    exit 1
fi

# Verify SHA256 checksum
if curl -fsSL --connect-timeout 5 --max-time 10 "${BASE_URL}/SHA256SUMS" -o "${SUMS_TMP}" 2>/dev/null; then
    EXPECTED=$(grep "${BINARY}$" "${SUMS_TMP}" | awk '{print $1}' || true)
    if [ -n "${EXPECTED}" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum "${TMP_BIN}" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "${TMP_BIN}" | awk '{print $1}')
        else
            ACTUAL=""
        fi
        if [ -n "${ACTUAL}" ]; then
            if [ "${EXPECTED}" = "${ACTUAL}" ]; then
                echo "[cred-mcp] Checksum verified"
            else
                echo "[cred-mcp] ERROR: Checksum mismatch! Expected: ${EXPECTED}, Got: ${ACTUAL}" >&2
                exit 1
            fi
        fi
    else
        echo "[cred-mcp] WARNING: ${BINARY} not found in SHA256SUMS, skipping verification" >&2
    fi
fi

mv "${TMP_BIN}" "${BIN_PATH}"
chmod +x "${BIN_PATH}"
echo "[cred-mcp] Ready: ${BIN_PATH}"
