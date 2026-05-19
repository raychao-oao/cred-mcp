#!/bin/bash
# Ensure the binary is installed before starting cred-mcp.
# This wrapper is the entrypoint in .mcp.json so that "plugin update"
# (which skips install.sh) still gets a working binary on next launch.

set -e

if [ -z "${CLAUDE_PLUGIN_ROOT}" ]; then
    echo "[cred-mcp] ERROR: CLAUDE_PLUGIN_ROOT is not set" >&2
    exit 1
fi

BIN="${CLAUDE_PLUGIN_ROOT}/bin/cred-mcp"

if [ ! -x "${BIN}" ]; then
    bash "${CLAUDE_PLUGIN_ROOT}/scripts/install.sh"
fi

exec "${BIN}" "$@"
