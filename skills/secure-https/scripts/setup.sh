#!/bin/bash
set -e

# Claude HTTPS MCP — Setup Script
# Installs the MCP server and registers it with Claude Code.

echo "=== Claude HTTPS MCP Setup ===" >&2

# --- Prerequisites ---

# Check Node.js
if ! command -v node &> /dev/null; then
  echo "Error: Node.js is not installed. Install Node.js 18+ from https://nodejs.org" >&2
  exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo "Error: Node.js 18+ is required (found v$(node -v))" >&2
  exit 1
fi

echo "Node.js $(node -v) detected" >&2

# Check Claude Code
if ! command -v claude &> /dev/null; then
  echo "Error: Claude Code CLI is not installed." >&2
  echo "Install it from: https://docs.anthropic.com/en/docs/claude-code" >&2
  exit 1
fi

echo "Claude Code CLI detected" >&2

# --- Install ---

echo "Installing claude-https-mcp..." >&2
npm install -g claude-https-mcp

echo "Registering MCP server with Claude Code..." >&2
claude mcp add --scope user --transport stdio cyphers-ai -- claude-https-mcp

# --- Config ---

CONFIG_DIR="$HOME/.claude"
CONFIG_FILE="$CONFIG_DIR/https-config.json"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Creating default configuration at $CONFIG_FILE..." >&2
  mkdir -p "$CONFIG_DIR"

  # Locate the example config from the installed package
  EXAMPLE_CONFIG=$(npm root -g)/claude-https-mcp/example-config.json

  if [ -f "$EXAMPLE_CONFIG" ]; then
    cp "$EXAMPLE_CONFIG" "$CONFIG_FILE"
    echo "Copied example config. Edit $CONFIG_FILE to match your environment." >&2
  else
    # Fallback: create a minimal config
    cat > "$CONFIG_FILE" << 'CONFIGEOF'
{
  "tls": {
    "minVersion": "TLSv1.2",
    "maxVersion": "TLSv1.3",
    "cipherProfile": "intermediate",
    "rejectUnauthorized": true
  },
  "ca": {
    "mode": "bundled"
  },
  "defaults": {
    "timeoutMs": 30000,
    "maxBodySizeBytes": 10485760
  }
}
CONFIGEOF
    echo "Created minimal config. Edit $CONFIG_FILE to match your environment." >&2
  fi
else
  echo "Configuration already exists at $CONFIG_FILE (skipped)" >&2
fi

# --- Verify ---

echo "" >&2
echo "=== Setup Complete ===" >&2
echo "Restart Claude Code to activate the SecureWebFetch tool." >&2
echo "Configuration: $CONFIG_FILE" >&2
